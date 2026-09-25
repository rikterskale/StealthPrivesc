using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

namespace StealthPrivesc {
    public static class NativeFsSearch {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern IntPtr FindFirstFile(string name, out long finder);
        [DllImport("kernel32.dll")] static extern bool FindNextFile(IntPtr handle, ref long finder);
        [DllImport("kernel32.dll")] static extern bool FindClose(IntPtr handle);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern IntPtr CreateFile(string name, uint access, uint share, IntPtr security, int creation, uint flags, IntPtr template);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool ReadFile(IntPtr handle, IntPtr buffer, uint size, out uint read, IntPtr overlapped);
        [StructLayout(LayoutKind.Sequential)] struct Win32 { public uint Attributes; public long Creation, LastAccess, LastWrite, Change; public uint LengthHigh, Length, Cluster, Index; [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string Name; [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)] public byte[] Tag; }
        internal static bool IsMatch(string name, Regex pattern, string path, Regex whole) {
            if (whole != null) { return whole.IsMatch(path); }
            return pattern.IsMatch(name);
        }
        public static SearchResult Search(string root, string pattern, string whole, int maximum, int seconds, int depth) {
            var result = new SearchResult();
            if (maximum <= 0 || depth <= 0) { return result; }
            Regex wholeRegex = whole == null ? null : RegexOptions(whole);
            var queue = new Queue<Tuple<string, int>>();
            queue.Enqueue(Tuple.Create(root, 0));
            DateTime stop = DateTime.UtcNow.AddSeconds(seconds < 0 ? 0x7FFFFFFF : seconds);
            while (queue.Count > 0) {
                if (DateTime.UtcNow >= stop) { result.TimeBudget = true; break; }
                var next = queue.Dequeue();
                if (next.Item2 > depth) { continue; }
                string current = next.Item1;
                if (!current.EndsWith("\\")) { current += "\\"; }
                IntPtr directory;
                long entry;
                directory = FindFirstFile(current + "*", out entry);
                if (directory == IntPtr.Zero) {
                    int error = Marshal.GetLastWin32Error();
                    if (error != 3 && error != 14 && error != 5 && error != 8 && error != 267) {
                        if (result.Error == null) { result.Error = error.ToString(CultureInfo.InvariantCulture); }
                    }
                    result.Inaccessible++;
                    continue;
                }
                var item = (Win32)Marshal.PtrToStructure(new IntPtr(entry + 0), typeof(Win32));
                while (true) {
                    if (!string.Equals(item.Name, ".", StringComparison.Ordinal) && !string.Equals(item.Name, "..", StringComparison.Ordinal)) {
                        string child = current + item.Name;
                        bool folder = (item.Attributes & 0x10) != 0;
                        if (!folder) {
                            result.Visited++;
                            if (result.Items.Count < maximum && (wholeRegex == null ? Regex.IsMatch(item.Name, pattern, System.Text.RegularExpressions.RegexOptions.IgnoreCase) : wholeRegex.IsMatch(child))) {
                                var entry2 = new FileEntry {
                                    Path = child, Name = item.Name, Length = unchecked((long)item.Length + ((long)item.LengthHigh << 32)),
                                    Creation = ((DateTime)DateTime.FromFileTimeUtc(item.Creation)).Ticks,
                                    LastAccess = ((DateTime)DateTime.FromFileTimeUtc(item.LastAccess)).Ticks,
                                    LastWrite = ((DateTime)DateTime.FromFileTimeUtc(item.LastWrite)).Ticks,
                                    Attributes = item.Attributes,
                                };
                                result.Items.Add(entry2);
                                if (result.Items.Count >= maximum) { result.Truncated = true; }
                            }
                        } else {
                            if ((item.Attributes & 0x400) != 0) {
                                if (result.Visited < 0x100000) { /* skip hidden */ }
                            } else if (result.Visited < 0x20000) {
                                if (!string.Equals(item.Name, "System Volume Information", StringComparison.OrdinalIgnoreCase) && !string.Equals(item.Name, "$RECYCLE.BIN", StringComparison.OrdinalIgnoreCase) && !string.Equals(item.Name, "$Extend", StringComparison.OrdinalIgnoreCase)) {
                                    queue.Enqueue(Tuple.Create(child, next.Item2 + 1));
                                }
                            }
                        }
                    }
                    if (result.Items.Count >= maximum) { result.Truncated = true; }
                    if (!FindNextFile(directory, ref entry)) { break; }
                    item = (Win32)Marshal.PtrToStructure(new IntPtr(entry + 0), typeof(Win32));
                    if (result.Truncated) { break; }
                }
                if (directory != IntPtr.Zero) { FindClose(directory); }
            }
            return result;
        }
        internal static Regex RegexOptions(string pattern) { return new Regex(pattern, System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.CultureInvariant); }
        public static HiveResult Hive(string hive, bool probe, bool write) {
            var result = new HiveResult();
            IntPtr handle = IntPtr.Zero;
            try {
                uint share, access;
                if (probe) { share = (uint)(0x1 | 0x2 | 0x4); access = (uint)(0x80000000 | 0x40000000); }
                else { share = 0x3; access = 0x80000000; }
                handle = CreateFile(hive, access, share, IntPtr.Zero, 3, 0x2000000, IntPtr.Zero);
                if (handle == IntPtr.Zero) {
                    result.Error = Marshal.GetLastWin32Error();
                    if (!(result.Error == 5 || result.Error == 7 || result.Error == 13 || result.Error == 32)) { result.Opened = false; }
                    return result;
                }
                if (!probe) {
                    IntPtr buffer = Marshal.AllocHGlobal(0x20);
                    try {
                        uint read;
                        if (!ReadFile(handle, buffer, 0x20, out read, IntPtr.Zero) || read < 0x20) {
                            result.Error = Marshal.GetLastWin32Error();
                            return result;
                        }
                        var magic = new byte[4];
                        for (int i = 0; i < 4; i++) { magic[i] = (byte)Marshal.ReadByte(buffer, i); }
                        if (!string.Equals(Encoding.ASCII.GetString(magic), "regf", StringComparison.Ordinal)) {
                            result.Error = unchecked((int)0xC000000D);
                            return result;
                        }
                    } finally { Marshal.FreeHGlobal(buffer); }
                }
                result.Opened = true;
                return result;
            } finally {
                if (handle != IntPtr.Zero) { CloseHandle(handle); }
            }
        }
        public static LnkResult Lnk(string file, bool read) {
            var result = new LnkResult();
            IntPtr handle = IntPtr.Zero;
            IntPtr buffer = IntPtr.Zero;
            try {
                handle = CreateFile(file, 0x80100, 0x3, IntPtr.Zero, 3, 0, IntPtr.Zero);
                if (handle == IntPtr.Zero) { result.Error = Marshal.GetLastWin32Error(); return result; }
                uint size;
                if (!GetFileSize(handle, out size, IntPtr.Zero)) { result.Error = Marshal.GetLastWin32Error(); return result; }
                if (size < 0x4C || size > 0x40000) { result.Error = unchecked((int)0xC0000004); return result; }
                buffer = Marshal.AllocHGlobal(new IntPtr(unchecked((long)size)));
                uint got;
                if (!ReadFile(handle, buffer, size, out got, IntPtr.Zero) || got < 0x4C) { result.Error = Marshal.GetLastWin32Error(); return result; }
                if (Marshal.ReadInt32(buffer, 0) != 0x4C504B) { result.Error = unchecked((int)0xC000000D); return result; }
                ulong flags = (ulong)Marshal.ReadInt32(buffer, 0x14);
                int info = Marshal.ReadInt32(buffer, 0x28);
                int extra = Marshal.ReadInt32(buffer, 0x3C);
                if ((flags & 1) != 0 && extra > 0 && extra + 0x14 < size) {
                    result.Target = ReadName(buffer, extra);
                } else if ((flags & 0x10) != 0) {
                    int name = Marshal.ReadInt32(buffer, 0x30);
                    int path = Marshal.ReadInt32(buffer, 0x34);
                    if (path > 0 && path + name < size) {
                        result.Target = Marshal.PtrToStringUni(IntPtr.Add(buffer, path), (name / 2) - 1);
                    }
                }
                if (result.Target == null && info > 0 && info < size) {
                    int kind = Marshal.ReadInt32(buffer, info);
                    if (kind == 1 || kind == 2) {
                        int offset = info + 12;
                        int length = Marshal.ReadInt32(buffer, offset);
                        if (offset + 4 + length + 2 < size) {
                            result.Target = Marshal.PtrToStringUni(IntPtr.Add(buffer, offset + 4), (length / 2) - 1);
                        }
                    }
                }
                if (extra > 0 && extra + 4 < size) {
                    int cursor = extra;
                    while (cursor + 8 <= size) {
                        int id = Marshal.ReadInt32(buffer, cursor);
                        int value = Marshal.ReadInt32(buffer, cursor + 4);
                        if (value == 0) { break; }
                        if (cursor + 8 + value > size) { break; }
                        string text = Marshal.PtrToStringUni(IntPtr.Add(buffer, cursor + 8), (value / 2) - 1);
                        if (id == 1) { result.WorkDir = text; }
                        else if (id == 2) { result.CmdLine = text; }
                        else if (id == 4) { result.Icon = text; }
                        else if (id == 5) { result.Relative = text; }
                        if ((value & 1) == 0) { break; }
                        cursor += 8 + value;
                    }
                }
                if (result.Target != null && result.Relative != null) {
                    string work = result.WorkDir == null ? System.IO.Path.GetDirectoryName(file) : result.WorkDir;
                    if (!string.IsNullOrEmpty(work)) {
                        string combined = System.IO.Path.Combine(work, result.Target.Replace('\\', System.IO.Path.DirectorySeparatorChar));
                        try { result.Target = System.IO.Path.GetFullPath(combined); } catch { }
                    }
                }
                return result;
            } catch {
                result.Error = 999;
                return result;
            } finally {
                if (buffer != IntPtr.Zero) { Marshal.FreeHGlobal(buffer); }
                if (handle != IntPtr.Zero) { CloseHandle(handle); }
            }
        }
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetFileSize(IntPtr handle, out uint low, IntPtr high);
        internal static string ReadName(IntPtr source, int offset) {
            int length = Marshal.ReadInt32(source, offset + 4);
            if (offset + 8 + length > 0 && length > 0 && (length & 1) == 0) {
                return Marshal.PtrToStringUni(IntPtr.Add(source, offset + 8), (length / 2) - 1);
            }
            return null;
        }
        public static PcapFile Pcap(string file, int maximum) {
            var result = new PcapFile();
            IntPtr handle = IntPtr.Zero;
            IntPtr buffer = IntPtr.Zero;
            try {
                handle = CreateFile(file, 0x80100, 0x3, IntPtr.Zero, 3, 0, IntPtr.Zero);
                if (handle == IntPtr.Zero) { result.Error = Marshal.GetLastWin32Error(); return result; }
                uint size;
                if (!GetFileSize(handle, out size, IntPtr.Zero)) { result.Error = Marshal.GetLastWin32Error(); return result; }
                if (size < 0x1C) { result.Error = unchecked((int)0xC0000004); return result; }
                buffer = Marshal.AllocHGlobal(new IntPtr(unchecked((long)(size < 0x400000 ? size : 0x400000))));
                uint read;
                if (!ReadFile(handle, buffer, size, out read, IntPtr.Zero) || read < 0x1C) { result.Error = Marshal.GetLastWin32Error(); return result; }
                int magic = Marshal.ReadInt32(buffer, 0);
                result.Version = (magic == 0xD4C3B2A1 || magic == 0xD4C3B2A0) ? 2 : 3;
                result.Network = Marshal.ReadInt32(buffer, 0x14);
                int cursor = 0x1C;
                bool big = (magic & 0xF) != 0 || magic == unchecked((int)0xA1B2C3D4);
                while (cursor + 0x14 <= (int)size && result.Packets.Count < maximum) {
                    uint sec = big ? ((uint)(byte)Marshal.ReadInt32(buffer, cursor) << 24) | ((uint)(byte)Marshal.ReadInt32(buffer, cursor + 4) << 16) : (uint)Marshal.ReadInt32(buffer, cursor);
                    uint frac = big ? (uint)(byte)Marshal.ReadInt32(buffer, cursor + 8) : (uint)Marshal.ReadInt32(buffer, cursor + 8);
                    uint length = big ? (uint)((byte)Marshal.ReadInt32(buffer, cursor + 12) << 24 | (byte)Marshal.ReadInt32(buffer, cursor + 16) << 16) : (uint)Marshal.ReadInt32(buffer, cursor + 12);
                    if (length > 0x100000) { break; }
                    string proto = "UNKNOWN";
                    int frame = cursor + 0x14;
                    if (result.Network == 1 && frame + 0x3C <= (int)read && cursor + 0x14 + length <= (int)read) {
                        ushort type = (ushort)((byte)Marshal.ReadByte(buffer, frame + 12) << 8 | (byte)Marshal.ReadByte(buffer, frame + 13));
                        if (type == 0x0800) { proto = "IP"; }
                        else if (type == 0x86DD) { proto = "IPv6"; }
                        else if (type == 0x0806) { proto = "ARP"; }
                        else if (type == 0x8100) { proto = "802.1Q"; }
                    }
                    result.Packet++;
                    result.Bytes += (int)length;
                    result.Packets.Add(string.Format(CultureInfo.InvariantCulture, "{0}:{1}:{2}:{3}", sec, frac, length, proto));
                    cursor += 0x14 + (int)length;
                }
                return result;
            } catch {
                result.Error = 999;
                return result;
            } finally {
                if (buffer != IntPtr.Zero) { Marshal.FreeHGlobal(buffer); }
                if (handle != IntPtr.Zero) { CloseHandle(handle); }
            }
        }
    }
}
