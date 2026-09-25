using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace StealthPrivesc {
    public sealed class RegValue {
        public string Name; public uint Type; public object Data; public bool Volatile; public int Error;
    }
    public sealed class RegKey {
        public string Path; public RegValue[] Values = new RegValue[0]; public string[] Subkeys = new string[0]; public int Error; public bool Truncated;
    }
    public static class NativeRegistry {
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern IntPtr RegOpenKeyEx(IntPtr hkey, string subkey, uint options, uint desired, out IntPtr result);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern int RegEnumKeyEx(IntPtr key, uint index, StringBuilder name, ref uint size, IntPtr cls, IntPtr times);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern int RegEnumValue(IntPtr key, uint index, StringBuilder name, ref uint size, IntPtr cls, ref uint type, IntPtr data, ref uint cap, IntPtr times);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern int RegQueryValueEx(IntPtr key, string value, IntPtr reserved, ref uint type, IntPtr data, ref uint size);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern IntPtr RegGetValue(IntPtr root, string subkey, string value, uint options, ref uint type, IntPtr data, ref uint size);
        [DllImport("advapi32.dll")] static extern int RegCloseKey(IntPtr key);
        internal static IntPtr Root(string hive) {
            if (hive.StartsWith("HKLM", StringComparison.OrdinalIgnoreCase)) { return new IntPtr(unchecked((int)0x80000002)); }
            if (hive.StartsWith("HKCU", StringComparison.OrdinalIgnoreCase)) { return new IntPtr(unchecked((int)0x80000001)); }
            if (hive.StartsWith("HKCR", StringComparison.OrdinalIgnoreCase)) { return new IntPtr(unchecked((int)0x80000000)); }
            if (hive.StartsWith("HKCC", StringComparison.OrdinalIgnoreCase)) { return new IntPtr(unchecked((int)0x80000005)); }
            if (hive.StartsWith("HKPD", StringComparison.OrdinalIgnoreCase)) { return new IntPtr(unchecked((int)0x80000020)); }
            if (hive.StartsWith("HKU", StringComparison.OrdinalIgnoreCase)) { return new IntPtr(unchecked((int)0x80000003)); }
            return IntPtr.Zero;
        }
        internal static (IntPtr hkey, string subkey) Split(string path) {
            if (string.IsNullOrEmpty(path)) { return (IntPtr.Zero, null); }
            string hive, rest;
            int colon = path.IndexOf(':');
            if (colon > 0) { hive = path.Substring(0, colon); rest = path.Substring(colon + 1); }
            else {
                int slash = path.IndexOf('\\');
                if (slash > 0) { hive = path.Substring(0, slash); rest = path.Substring(slash + 1); }
                else { hive = path; rest = null; }
            }
            if (!string.IsNullOrEmpty(rest)) { while (rest.StartsWith("\\")) { rest = rest.Substring(1); } if (rest.Length == 0) { rest = null; } }
            return (Root(hive), rest);
        }
        internal static byte[] Copy(IntPtr buffer, int length) {
            var data = new byte[length];
            if (length > 0) { Marshal.Copy(buffer, data, 0, length); }
            return data;
        }
        internal static string Wstring(byte[] data) {
            int length = data.Length;
            while (length >= 2 && data[length - 1] == 0 && data[length - 2] == 0) { length -= 2; }
            return Encoding.Unicode.GetString(data, 0, length);
        }
        internal static string[] Multi(byte[] data) {
            var list = new List<string>();
            int cursor = 0;
            while (cursor + 1 < data.Length) {
                int end = cursor;
                while (end + 1 < data.Length && !(data[end] == 0 && data[end + 1] == 0)) { end += 2; }
                if (end > cursor) { var part = new byte[end - cursor]; Array.Copy(data, cursor, part, 0, end - cursor); list.Add(Wstring(part)); }
                if (end + 1 >= data.Length) { break; }
                cursor = end + 2;
            }
            return list.ToArray();
        }
        internal static object Decode(uint type, IntPtr buffer, int length) {
            if (length == 0) { return new byte[0]; }
            switch (type) {
                case 1: return Wstring(Copy(buffer, length));
                case 2: return Wstring(Copy(buffer, length));
                case 3: return Copy(buffer, length);
                case 4: return (uint)Marshal.ReadInt32(buffer, 0);
                case 5: return (uint)Marshal.ReadInt32(buffer, 0);
                case 7: return Multi(Copy(buffer, length));
                case 11: return (ulong)Marshal.ReadInt64(buffer, 0);
                default: return "0x" + type.ToString("X");
            }
        }
        public static RegKey Enumerate(string path, int maximum, int maxValue, int options, bool hot) {
            var key = new RegKey { Path = path };
            IntPtr hive, result; string subkey;
            (hive, subkey) = Split(path);
            if (hive == IntPtr.Zero) { key.Error = 8; return key; }
            uint flags = hot ? 0x4001u : 0x1u;
            if (IntPtr.Zero == (result = RegOpenKeyEx(hive, string.IsNullOrEmpty(subkey) ? null : subkey, unchecked((uint)options), flags, out IntPtr probe))) { key.Error = Marshal.GetLastWin32Error(); return key; }
            try {
                var sub = new StringBuilder(0x400);
                for (uint index = 0; ; index++) {
                    if (sub.Capacity < 0x400) { sub.Capacity = 0x400; }
                    uint subbuf = (uint)sub.Capacity;
                    int status = RegEnumKeyEx(result, index, sub, ref subbuf, IntPtr.Zero, IntPtr.Zero);
                    if (status == 259) { key.Truncated = true; break; }
                    if (status != 0) { if (key.Error == 0) { key.Error = status; } break; }
                    Array.Resize(ref key.Subkeys, key.Subkeys.Length + 1);
                    key.Subkeys[key.Subkeys.Length - 1] = sub.ToString();
                    if (maximum > 0 && key.Subkeys.Length >= maximum) { key.Truncated = true; break; }
                }
                var values = new List<RegValue>();
                var name = new StringBuilder(0x200);
                for (uint index = 0; ; index++) {
                    if (name.Capacity < 0x200) { name.Capacity = 0x200; }
                    uint namebuf = (uint)name.Capacity, cap = 0, vtype = 0;
                    int status = RegEnumValue(result, index, name, ref namebuf, IntPtr.Zero, ref vtype, IntPtr.Zero, ref cap, IntPtr.Zero);
                    if (status == 259) { key.Truncated = true; break; }
                    if (status != 0) { if (key.Error == 0) { key.Error = status; } break; }
                    var entry = Read(result, name.ToString(), vtype, maxValue);
                    if (entry != null) { values.Add(entry); }
                    if (maximum > 0 && values.Count >= maximum) { key.Truncated = true; break; }
                }
                key.Values = values.ToArray();
                return key;
            } finally { RegCloseKey(result); }
        }
        internal static RegValue Read(IntPtr key, string name, uint type, int maxValue) {
            if (string.IsNullOrEmpty(name)) { name = "(default)"; }
            var value = new RegValue { Name = name, Type = type };
            uint regType = 0, length = 0;
            int status = RegQueryValueEx(key, name, IntPtr.Zero, ref regType, IntPtr.Zero, ref length);
            if (status != 0) { value.Error = status; return value; }
            if (length > 0 && length > maxValue) { value.Error = 12; value.Data = null; value.Type = regType; value.Name = name; return value; }
            if (length == 0) { value.Data = new byte[0]; value.Type = regType; value.Name = name; return value; }
            IntPtr buffer;
            buffer = Marshal.AllocHGlobal(new IntPtr(unchecked((long)length)));
            try {
                if (RegQueryValueEx(key, name, IntPtr.Zero, ref regType, buffer, ref length) != 0) { value.Error = Marshal.GetLastWin32Error(); value.Name = name; value.Type = regType; return value; }
                value.Data = Decode(regType, buffer, (int)length);
                value.Name = name; value.Type = regType;
                return value;
            } finally { Marshal.FreeHGlobal(buffer); }
        }
        public static RegValue Single(string path, string value, int maxValue, bool hot) {
            var result = new RegValue { Name = value };
            IntPtr hive; string subkey;
            (hive, subkey) = Split(path);
            if (hive == IntPtr.Zero) { result.Error = 8; return result; }
            string sub = string.IsNullOrEmpty(subkey) ? null : subkey;
            uint flags = hot ? 0x4000u : 0u;
            uint type = 0, size = 0;
            int status = (int)RegGetValue(hive, sub, value, flags, ref type, IntPtr.Zero, ref size);
            if (status != 0) { result.Error = status; result.Type = type; return result; }
            if (size > (uint)maxValue) { result.Error = 12; return result; }
            if (size == 0) { result.Type = type; result.Data = new byte[0]; return result; }
            IntPtr buffer = Marshal.AllocHGlobal(new IntPtr(unchecked((long)size)));
            try {
                if ((int)RegGetValue(hive, sub, value, flags, ref type, buffer, ref size) != 0) { result.Error = Marshal.GetLastWin32Error(); return result; }
                result.Type = type;
                result.Data = Decode(type, buffer, (int)size);
                return result;
            } finally { Marshal.FreeHGlobal(buffer); }
        }
    }
}
