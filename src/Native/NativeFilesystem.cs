using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;

namespace StealthPrivesc {
    public sealed class FileEntry {
        public string Path, Name;
        public long Length, Creation, LastWrite, LastAccess;
        public uint Attributes, ReparseTag;
        public string Owner, Descriptor, Sha1, Sha256;
        public string Company, FileVersion, Internal, Original, Product, Description;
        public int Error;
    }
    public sealed class LnkResult { public string Target, Arguments, WorkDir, Icon, Relative, CmdLine; public int Error; }
    public sealed class PcapFile { public int Version, Network, Packet, Bytes, Error; public List<string> Packets = new List<string>(); }
    public sealed class HiveResult { public bool Opened; public int Error; }
    public sealed class SearchResult {
        public List<FileEntry> Items = new List<FileEntry>();
        public int Visited, Inaccessible; public bool Truncated, TimeBudget; public string Error;
    }
    public static class NativeFilesystem {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern IntPtr CreateFile(string name, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool ReadFile(IntPtr handle, IntPtr buffer, uint size, out uint read, IntPtr overlapped);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetFileTime(IntPtr handle, out long created, out long accessed, out long written);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetFileSizeEx(IntPtr handle, out long size);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool GetSecurityInfo(IntPtr handle, uint type, IntPtr security, out IntPtr owner, out IntPtr group, IntPtr dacl, IntPtr sacl, IntPtr descriptor);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool SidToStringSid(IntPtr sid, out IntPtr text);
        [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr pointer);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern uint GetFileVersionInfoSize(string file, out IntPtr needed);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool GetFileVersionInfo(string file, uint size, IntPtr buffer);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool VerQueryValue(IntPtr version, string key, out IntPtr block, out uint length);
        [DllImport("bcrypt.dll", SetLastError = true)] static extern uint BCryptOpenAlgorithmProvider(out IntPtr handle, string algorithm, string library, uint flags);
        [DllImport("bcrypt.dll", SetLastError = true)] static extern uint BCryptGetProperty(IntPtr handle, string property, IntPtr output, uint size, out uint needed, uint flags);
        [DllImport("bcrypt.dll", SetLastError = true)] static extern uint BCryptHashObject(IntPtr algorithm, IntPtr output, uint size, IntPtr input, uint length, IntPtr parameters, uint flags);
        [DllImport("bcrypt.dll")] static extern void BCryptCloseAlgorithmProvider(IntPtr handle, uint flags);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern IntPtr FindFirstFile(string name, out long finder);
        [DllImport("kernel32.dll")] static extern bool FindNextFile(IntPtr handle, ref long finder);
        [DllImport("kernel32.dll")] static extern bool FindClose(IntPtr handle);
        [StructLayout(LayoutKind.Sequential)] struct Find { public uint Attributes; public long Creation, LastAccess, LastWrite, Change; public uint LengthHigh, Length, Cluster, Index; [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string Name; [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)] public byte[] Tag; }
        internal static long Ticks(long filetime) { return ((DateTime)DateTime.FromFileTimeUtc(filetime)).Ticks; }
        internal static string Hex(byte[] bytes) {
            var builder = new StringBuilder(bytes.Length * 2);
            foreach (byte value in bytes) { builder.Append(value.ToString("x2", CultureInfo.InvariantCulture)); }
            return builder.ToString();
        }
        internal static string Uni(IntPtr block, int chars) { return block == IntPtr.Zero ? null : Marshal.PtrToStringUni(block, chars); }
        internal static string Version(IntPtr version, string key) {
            IntPtr block; uint length;
            if (!VerQueryValue(version, "\\" + key, out block, out length) || length == 0) { return null; }
            string text = Uni(block, (int)(length / 2));
            return string.IsNullOrEmpty(text) ? null : text;
        }
        internal static void VersionBlock(IntPtr version, out string company, out string file, out string internal, out string original, out string product, out string description) {
            IntPtr translation;
            if (!VerQueryValue(version, "\\VarFileInfo\\Translation", out translation, out uint unused) || translation == IntPtr.Zero) {
                company = file = internal = original = product = description = null;
                return;
            }
            int language = (ushort)Marshal.ReadInt16(translation, 0);
            int codepage = (ushort)Marshal.ReadInt16(translation, 2);
            string prefix = string.Format(CultureInfo.InvariantCulture, "\\StringFileInfo\\{0:x4}{1:x4}\\", language, codepage);
            company = Version(version, prefix + "CompanyName");
            file = Version(version, prefix + "FileVersion");
            internal = Version(version, prefix + "InternalName");
            original = Version(version, prefix + "OriginalFilename");
            product = Version(version, prefix + "ProductName");
            description = Version(version, prefix + "FileDescription");
        }
        internal static string Digest(IntPtr handle, string algorithm) {
            IntPtr provider;
            uint status = BCryptOpenAlgorithmProvider(out provider, algorithm, IntPtr.Size == 8 ? "RSA" : null, 0);
            if (status != 0) { throw new Win32Exception((int)status); }
            IntPtr digest;
            try {
                IntPtr value;
                uint needed, length = 0;
                status = BCryptGetProperty(provider, "ObjectLength", IntPtr.Zero, 0, out needed, 0);
                if (status != 0) { throw new Win32Exception((int)status); }
                value = Marshal.AllocHGlobal(needed);
                try {
                    if (BCryptGetProperty(provider, "ObjectLength", value, needed, out needed, 0) != 0) { throw new Win32Exception(0xC000000D); }
                    length = (uint)Marshal.ReadInt32(value);
                    digest = Marshal.AllocHGlobal(length);
                    byte[] chunk = new byte[0x10000];
                    IntPtr buffer = Marshal.AllocHGlobal(chunk.Length);
                    try {
                        while (true) {
                            uint read;
                            if (!ReadFile(handle, buffer, (uint)chunk.Length, out read, IntPtr.Zero) && read == 0) { break; }
                            if (read == 0) { break; }
                            if (BCryptHashObject(provider, digest, length, buffer, read, IntPtr.Zero, 0) != 0) { throw new Win32Exception(0xC000000E); }
                        }
                    } finally { Marshal.FreeHGlobal(buffer); }
                    var result = new byte[length];
                    Marshal.Copy(digest, result, 0, (int)length);
                    return Hex(result);
                } finally {
                    Marshal.FreeHGlobal(value);
                    Marshal.FreeHGlobal(digest);
                }
            } finally { BCryptCloseAlgorithmProvider(provider, 0); }
        }
        internal static FileEntry Inspect(string path, bool hash, string algorithm, bool version, bool security, bool descriptor) {
            var result = new FileEntry { Path = path, Name = path.Substring(path.LastIndexOf('\\') + 1) };
            IntPtr handle = IntPtr.Zero;
            try {
                handle = CreateFile(path, 0x80100 | 0x20, 0x7, IntPtr.Zero, 3, 0x2000000, IntPtr.Zero);
                if (handle == IntPtr.Zero) {
                    int error = Marshal.GetLastWin32Error();
                    result.Error = error;
                    if (error == 5 || error == 7 || error == 13 || error == 32) { return result; }
                    throw new Win32Exception(error);
                }
                long created, accessed, written, length;
                if (!GetFileTime(handle, out created, out accessed, out written)) { result.Error = Marshal.GetLastWin32Error(); return result; }
                if (!GetFileSizeEx(handle, out length)) { result.Error = Marshal.GetLastWin32Error(); return result; }
                result.Length = length;
                result.Creation = Ticks(created);
                result.LastAccess = Ticks(accessed);
                result.LastWrite = Ticks(written);
                if (hash && !string.IsNullOrEmpty(algorithm)) {
                    if (algorithm == "SHA1") { result.Sha1 = Digest(handle, "SHA1"); } else { result.Sha256 = Digest(handle, "SHA256"); }
                }
                if (version) {
                    IntPtr needed;
                    uint found = GetFileVersionInfoSize(path, out needed);
                    if (found != 0 && needed != IntPtr.Zero) {
                        IntPtr block = Marshal.AllocHGlobal(needed.ToInt64());
                        try {
                            if (GetFileVersionInfo(path, found, block)) { VersionBlock(block, out result.Company, out result.FileVersion, out result.Internal, out result.Original, out result.Product, out result.Description); }
                        } finally { Marshal.FreeHGlobal(block); }
                    }
                }
                if (security) {
                    IntPtr owner, group, info;
                    if (!GetSecurityInfo(handle, 1, IntPtr.Zero, out owner, out group, IntPtr.Zero, IntPtr.Zero, out info)) {
                        result.Error = Marshal.GetLastWin32Error();
                    }
                    if (owner != IntPtr.Zero) {
                        IntPtr text;
                        if (SidToStringSid(owner, out text)) {
                            result.Owner = Uni(text, 0);
                            Marshal.FreeHGlobal(text);
                        }
                    }
                    if (descriptor && info != IntPtr.Zero) {
                        uint length;
                        IntPtr slot = Marshal.AllocHGlobal(4);
                        try {
                            if (QueryDescriptor(info, out IntPtr data, out length)) {
                                var blob = new byte[length];
                                Marshal.Copy(data, blob, 0, (int)length);
                                result.Descriptor = Convert.ToBase64String(blob);
                            }
                        } finally { Marshal.FreeHGlobal(slot); }
                    }
                }
                return result;
            } catch (Win32Exception ex) {
                if (result.Error == 0) { result.Error = ex.NativeErrorCode; }
                return result;
            } catch {
                if (result.Error == 0) { result.Error = 999; }
                return result;
            } finally {
                if (handle != IntPtr.Zero) { CloseHandle(handle); }
            }
        }
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool GetDescriptor(IntPtr source, IntPtr buffer, uint size, out uint returned);
        internal static bool QueryDescriptor(IntPtr source, out IntPtr data, out uint length) {
            data = IntPtr.Zero; length = 0;
            uint returned;
            if (!GetDescriptor(source, IntPtr.Zero, 0, out returned)) { return false; }
            length = returned;
            if (length == 0 || length > 0x200000) { return false; }
            data = Marshal.AllocHGlobal(length);
            if (!GetDescriptor(source, data, length, out returned)) { return false; }
            return true;
        }
    }
}
