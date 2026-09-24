using System;
using System.Collections.Generic;
using System.Globalization;
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
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern int RegEnumKeyEx(IntPtr key, uint index, StringBuilder name, ref uint size, IntPtr class, IntPtr times);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern int RegEnumValue(IntPtr key, uint index, StringBuilder name, ref uint size, IntPtr class, ref uint type, IntPtr data, ref uint value, IntPtr times);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern int RegQueryValueEx(IntPtr key, string value, IntPtr reserved, ref uint type, IntPtr data, ref uint size);
        [DllImport("advapi32.dll")] static extern int RegCloseKey(IntPtr key);
        [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr pointer);
        [DllImport("kernel32.dll")] static extern IntPtr RegCreateKey(IntPtr root, string subkey);
        [DllImport("kernel32.dll")] static extern IntPtr RegGetValue(IntPtr root, string subkey, string value, uint options, ref uint type, IntPtr data, ref uint size);
        internal static IntPtr Hives { get { } }
        internal static IntPtr Root(string hive) {
            if (hive.StartsWith("HKLM", StringComparison.OrdinalIgnoreCase)) { return new IntPtr(unchecked((int)0x80000002)); }
            if (hive.StartsWith("HKCU", StringComparison.OrdinalIgnoreCase)) { return new IntPtr(unchecked((int)0x80000001)); }
            if (hive.StartsWith("HKCR", StringComparison.OrdinalIgnoreCase)) { return new IntPtr(unchecked((int)0x80000000)); }
            if (hive.StartsWith("HKCC", StringComparison.OrdinalIgnoreCase)) { return new IntPtr(unchecked((int)0x80000005)); }
            return IntPtr.Zero;
        }
        public static (IntPtr hkey, string subkey) Split(string path) {
            if (string.IsNullOrEmpty(path)) { return (IntPtr.Zero, null); }
            string hive, rest;
            int separator = path.IndexOf(':');
            if (separator > 0) { hive = path.Substring(0, separator); rest = path.Substring(separator + 1); }
            else if (path.StartsWith("Registry::", StringComparison.OrdinalIgnoreCase)) { hive = path.Substring(10); rest = ""; }
            else { hive = path.Split('\\')[0]; rest = path.Length > 5 ? path.Substring(5) : ""; }
            while (rest.StartsWith("\\")) { rest = rest.Substring(1); }
            return (Root(hive), rest);
        }
        public static RegKey Enumerate(string path, int maximum, int maxValue, int options, bool volatile) {
            var key = new RegKey { Path = path };
            IntPtr hive, subkey = IntPtr.Zero;
            (hive, _) = Split(path);
            IntPtr result;
            uint desired = 0x1 | (volatile ? 0x4000 : 0);
            IntPtr root = RegOpenKeyEx(hive, string.IsNullOrEmpty(path) ? null : subkey, options, desired, out result);
            if (result == IntPtr.Zero) {
                key.Error = Marshal.GetLastWin32Error();
                if (key.Error != 2 && key.Error != 5) { }
                return key;
            }
            try {
                uint size = 0x100;
                StringBuilder name = new StringBuilder(0x100);
                for (uint index = 0; index < maximum; index++) {
                    if (name.Capacity < size + 2) { name.Capacity = (int)size + 2; }
                    name.Length = (int)size;
                    if (index < maximum) {
                        int status = RegEnumKeyEx(result, index, name, ref size, IntPtr.Zero, IntPtr.Zero);
                        if (status == 259) { key.Truncated = true; break; }
                        if (status != 0) { if (key.Error == 0) { key.Error = status; } break; }
                        var copy = (string)name.Clone();
                        Array.Resize(ref key.Subkeys, key.Subkeys.Length + 1);
                        key.Subkeys[key.Subkeys.Length - 1] = copy.ToString();
                    } else { break; }
                }
                var values = new List<RegValue>();
                for (uint index = 0; ; index++) {
                    if (name.Capacity < 0x100) { }
                    name.Length = 0x100;
                    int status = RegEnumValue(result, index, name, ref size, IntPtr.Zero, ref uint type, IntPtr.Zero, ref uint value, IntPtr.Zero);
                    if (status == 259) { key.Truncated = true; break; }
                    if (status != 0) { if (key.Error == 0) { key.Error = status; } break; }
                    var entry = Read(result, name.ToString(), type, maxValue);
                    if (entry != null) { values.Add(entry); }
                    if (maximum > 0 && values.Count >= maximum) { key.Truncated = true; break; }
                }
                key.Values = values.ToArray();
                return key;
            } finally { RegCloseKey(result); }
        }
        internal static RegValue Read(IntPtr key, string name, uint type, int maxValue) {
            var value = new RegValue { Name = name, Type = type };
            if (name.Length == 0) { name = "(default)"; value.Name = "(default)"; }
            uint length = 0;
            int probe = RegQueryValueEx(key, name, IntPtr.Zero, ref type, IntPtr.Zero, ref length);
            if (probe != 0) { value.Error = probe; if (probe != 2 && probe != 5) { } return value; }
            if (length == 0) { value.Data = new byte[0]; value.Type = type; value.Name = name; return value; }
            if (length > maxValue) { value.Error = 0xC0000023; value.Truncated = true; value.Name = name; value.Type = type; return value; }
            IntPtr buffer = Marshal.AllocHGlobal(length);
            try {
                if (RegQueryValueEx(key, name, IntPtr.Zero, ref type, buffer, ref length) != 0) {
                    value.Error = Marshal.GetLastWin32Error();
                    value.Name = name; value.Type = type;
                    return value;
                }
                if (type == 1) {
                    var bytes = new byte[length];
                    Marshal.Copy(buffer, bytes, 0, (int)length);
                    value.Data = new string(Encoding.Unicode.GetChars(bytes, 0, bytes.Length / 2 * 2), 0, bytes.Length / 2);
                } else if (type == 2) {
                    var bytes = new byte[length];
                    Marshal.Copy(buffer, bytes, 0, (int)length);
                    value.Data = bytes;
                } else if (type == 3) {
                    var bytes = new byte[length];
                    Marshal.Copy(buffer, bytes, 0, (int)length);
                    value.Data = bytes;
                } else if (type == 4) {
                    value.Data = (uint)Marshal.ReadInt32(buffer, 0);
                } else if (type == 5) {
                    value.Data = (ulong)Marshal.ReadInt64(buffer, 0);
                } else if (type == 7) {
                    var list = new List<string>();
                    var bytes = new byte[length];
                    Marshal.Copy(buffer, bytes, 0, (int)length);
                    int cursor = 0;
                    while (cursor + 2 < bytes.Length && !(bytes[cursor] == 0 && bytes[cursor + 1] == 0)) {
                        int next = cursor;
                        while (next + 1 < bytes.Length && !(bytes[next] == 0 && bytes[next + 1] == 0)) { next += 2; }
                        if (next > cursor) { list.Add(Encoding.Unicode.GetString(bytes, cursor, next - cursor)); }
                        cursor = next + 2;
                    }
                    value.Data = list.ToArray();
                } else if (type == 11) {
                    value.Data = (long)Marshal.ReadInt64(buffer, 0);
                } else {
                    value.Data = "0x" + type.ToString("X");
                }
                value.Name = name; value.Type = type;
                return value;
            } finally { Marshal.FreeHGlobal(buffer); }
        }
        public static RegValue Single(string path, string value, int maxValue, bool volatile) {
            var result = new RegValue { Name = value };
            IntPtr hive, subkey;
            (hive, _) = Split(path);
            IntPtr key;
            uint desired = 0x1 | (volatile ? 0x4000 : 0);
            IntPtr root = RegOpenKeyEx(hive, subkey, 0, desired, out key);
            if (key == IntPtr.Zero) { result.Error = Marshal.GetLastWin32Error(); return result; }
            try {
                uint type = 0, size = 0;
                int status = RegGetValue(root, null, value, volatile ? 0x4000 : 0, ref type, IntPtr.Zero, ref size);
                if (status == 0 && size > maxValue) {
                    result.Error = 0xC0000023;
                    return result;
                }
                if (status != 0) { result.Error = status; return result; }
                if (size == 0) { return new RegValue { Name = value, Type = type, Data = new byte[0] }; }
                IntPtr buffer = Marshal.AllocHGlobal(size);
                try {
                    status = RegGetValue(root, null, value, volatile ? 0x4000 : 0, ref type, buffer, ref size);
                    if (status != 0) { result.Error = status; return result; }
                    var copied = new byte[size];
                    Marshal.Copy(buffer, copied, 0, (int)size);
                    result.Type = type;
                    if (type == 1) { result.Data = new string(Encoding.Unicode.GetChars(copied, 0, copied.Length / 2 * 2), 0, copied.Length / 2); }
                    else if (type == 2 || type == 3) { result.Data = copied; }
                    else if (type == 4) { result.Data = (uint)Marshal.ReadInt32(buffer, 0); }
                    else if (type == 11) { result.Data = (long)Marshal.ReadInt64(buffer, 0); }
                    else if (type == 7) {
                        var list = new List<string>();
                        int cursor = 0;
                        while (cursor + 2 < copied.Length && !(copied[cursor] == 0 && copied[cursor + 1] == 0)) {
                            int next = cursor;
                            while (next + 1 < copied.Length && !(copied[next] == 0 && copied[next + 1] == 0)) { next += 2; }
                            if (next > cursor) { list.Add(Encoding.Unicode.GetString(copied, cursor, next - cursor)); }
                            cursor = next + 2;
                        }
                        result.Data = list.ToArray();
                    } else { result.Data = "0x" + type.ToString("X"); }
                    return result;
                } finally { Marshal.FreeHGlobal(buffer); }
            } finally { RegCloseKey(key); }
        }
    }
}
