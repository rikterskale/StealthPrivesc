using System;
using System.Collections.Generic;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;

namespace StealthPrivesc {
    public sealed class Hot { public string Id, Desc, Date, Ubr, Serv, Pack, Arch, Name, Type, Reboot, Fix, Sec; }
    public static class NativeSystem {
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern IntPtr RegOpenKeyEx(IntPtr root, string sub, uint opt, uint sam, out IntPtr key);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)] static extern IntPtr RegQueryValueEx(IntPtr key, string val, IntPtr res, ref uint type, IntPtr data, ref uint size);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)] static extern IntPtr RegEnumKeyEx(IntPtr key, uint index, StringBuilder name, ref uint size, IntPtr cls, IntPtr times);
        [DllImport("advapi32.dll")] static extern int RegCloseKey(IntPtr key);
        internal static IntPtr Lm { get { return new IntPtr(unchecked((int)0x80000002)); } }
        internal static IntPtr Cu { get { return new IntPtr(unchecked((int)0x80000001)); } }
        internal static bool Sub(IntPtr key, uint index, out string name, ref StringBuilder buf, ref uint size) {
            name = null; size = (uint)buf.Capacity;
            int rc = (int)RegEnumKeyEx(key, index, buf, ref size, IntPtr.Zero, IntPtr.Zero);
            if (rc != 0) { return false; }
            name = buf.ToString();
            return true;
        }
        internal static string Q(IntPtr key, string val, uint cap, out uint type) {
            type = 0; uint size = 0;
            if (0 != (int)RegQueryValueEx(key, val, IntPtr.Zero, ref type, IntPtr.Zero, ref size)) { return null; }
            if (size == 0 || size > cap) { return null; }
            IntPtr data = Marshal.AllocHGlobal(new IntPtr(unchecked((long)size)));
            try {
                if (0 != (int)RegQueryValueEx(key, val, IntPtr.Zero, ref type, data, ref size)) { return null; }
                if (type == 1) { return Marshal.PtrToStringUni(data, (int)(size / 2)); }
                if (type == 4) { return ((uint)Marshal.ReadInt32(data, 0)).ToString(CultureInfo.InvariantCulture); }
                if (type == 11) { return ((long)Marshal.ReadInt64(data, 0)).ToString(CultureInfo.InvariantCulture); }
                var bytes = new byte[size];
                Marshal.Copy(data, bytes, 0, (int)size);
                if (type == 3 || type == 2) { return Convert.ToBase64String(bytes); }
                if (type == 7) {
                    var items = new List<string>();
                    for (int cur = 0, nxt = 0; ; nxt += 2) {
                        if (nxt + 1 >= bytes.Length || (bytes[nxt] == 0 && bytes[nxt + 1] == 0)) {
                            if (nxt - cur > 0) { items.Add(Encoding.Unicode.GetString(bytes, cur, nxt - cur)); }
                            if (nxt + 1 >= bytes.Length) { break; }
                            cur = nxt + 2;
                        }
                    }
                    return string.Join(";", items);
                }
                return null;
            } finally { Marshal.FreeHGlobal(data); }
        }
        public static string Whoami() {
            IntPtr key; uint t;
            if (0 != (int)RegOpenKeyEx(Cu, "Environment", 0, 0x1, out key)) { return null; }
            try {
                string u = Q(key, "USERNAME", 0x400, out t), d = Q(key, "USERDOMAIN", 0x200, out t), c = Q(key, "COMPUTERNAME", 0x200, out t);
                return "user=" + (u ?? "") + ";domain=" + (d ?? "") + ";computer=" + (c ?? "");
            } finally { RegCloseKey(key); }
        }
        public static string Computer() {
            IntPtr key; uint t;
            var list = new List<string>();
            if (0 == (int)RegOpenKeyEx(Lm, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, 0x1, out key)) {
                list.Add("OS:" + (Q(key, "ProductName", 0x400, out t) ?? ""));
                list.Add("BUILD:" + (Q(key, "CurrentBuildNumber", 0x80, out t) ?? ""));
                list.Add("UBR:" + (Q(key, "UBR", 0x80, out t) ?? ""));
                list.Add("NAME:" + (Q(key, "EditionID", 0x80, out t) ?? ""));
                list.Add("BRANCH:" + (Q(key, "BuildBranch", 0x200, out t) ?? ""));
                RegCloseKey(key);
            }
            if (0 == (int)RegOpenKeyEx(Lm, "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment", 0, 0x1, out key)) {
                list.Add("COMPUTERNAME:" + (Q(key, "COMPUTERNAME", 0x200, out t) ?? ""));
                RegCloseKey(key);
            }
            if (0 == (int)RegOpenKeyEx(Cu, "Environment", 0, 0x1, out key)) {
                list.Add("USERDOMAIN:" + (Q(key, "USERDOMAIN", 0x200, out t) ?? ""));
                list.Add("USERNAME:" + (Q(key, "USERNAME", 0x400, out t) ?? ""));
                RegCloseKey(key);
            }
            return string.Join("\n", list);
        }
        public static string Profiles(int cap) {
            IntPtr key;
            if (0 != (int)RegOpenKeyEx(Lm, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList", 0, 0x1, out key)) { return null; }
            try {
                var list = new List<string>();
                var buf = new StringBuilder(0x200); uint size = 0x200; string name;
                for (uint index = 0; ; index++) {
                    if (!Sub(key, index, out name, ref buf, ref size)) { break; }
                    if (list.Count >= cap) { break; }
                    IntPtr sub;
                    if (0 == (int)RegOpenKeyEx(key, name, 0, 0x1, out sub)) {
                        try {
                            uint t; string img = Q(sub, "ProfileImagePath", 0x400, out t); string st = Q(sub, "State", 0x8, out t);
                            if (img != null) { list.Add(name + ":" + img + ":" + (st ?? "")); }
                        } finally { RegCloseKey(sub); }
                    }
                }
                return string.Join("\n", list);
            } finally { RegCloseKey(key); }
        }
        public static List<Hot> Hotfixes(int cap, out int miss) {
            miss = 0;
            var list = new List<Hot>();
            IntPtr key;
            if (0 != (int)RegOpenKeyEx(Lm, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Hotfixes", 0, 0x1, out key)) { return list; }
            try {
                var buf = new StringBuilder(0x100); uint size = 0x100; string name;
                for (uint index = 0; ; index++) {
                    if (!Sub(key, index, out name, ref buf, ref size)) { break; }
                    if (list.Count >= cap) { break; }
                    IntPtr sub;
                    if (0 == (int)RegOpenKeyEx(key, name, 0, 0x1, out sub)) {
                        try {
                            var h = new Hot { Id = name };
                            uint t;
                            h.Desc = Q(sub, "Description", 0x1000, out t);
                            h.Date = Q(sub, "InstalledOn", 0x80, out t);
                            h.Serv = Q(sub, "ServicePack", 0x80, out t);
                            h.Pack = Q(sub, "Pack", 0x40, out t);
                            h.Arch = Q(sub, "Architecture", 0x40, out t);
                            h.Name = Q(sub, "DisplayName", 0x400, out t);
                            h.Type = Q(sub, "Type", 0x80, out t);
                            h.Reboot = Q(sub, "RebootRequired", 0x80, out t);
                            h.Sec = Q(sub, "Severity", 0x80, out t);
                            list.Add(h);
                        } finally { RegCloseKey(sub); }
                    }
                }
                return list;
            } finally { RegCloseKey(key); }
        }
        public static string Shares(int cap) {
            IntPtr key;
            if (0 != (int)RegOpenKeyEx(Lm, "SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Shares", 0, 0x1, out key)) { return null; }
            try {
                var list = new List<string>();
                var buf = new StringBuilder(0x100); uint size = 0x100; string name;
                for (uint index = 0; ; index++) {
                    if (!Sub(key, index, out name, ref buf, ref size)) { break; }
                    if (list.Count >= cap) { break; }
                    IntPtr sub;
                    if (0 == (int)RegOpenKeyEx(key, name, 0, 0x1, out sub)) {
                        try {
                            uint t; string path = Q(sub, "Path", 0x400, out t); string typ = Q(sub, "Type", 0x8, out t);
                            list.Add(name + ":" + (path ?? "") + ":" + (typ ?? ""));
                        } finally { RegCloseKey(sub); }
                    }
                }
                return string.Join("\n", list);
            } finally { RegCloseKey(key); }
        }
        public static string Printers(int cap) {
            IntPtr key;
            if (0 != (int)RegOpenKeyEx(Lm, "SYSTEM\\CurrentControlSet\\Control\\Print\\Printers", 0, 0x1, out key)) { return null; }
            try {
                var list = new List<string>();
                var buf = new StringBuilder(0x100); uint size = 0x100; string name;
                for (uint index = 0; ; index++) {
                    if (!Sub(key, index, out name, ref buf, ref size)) { break; }
                    if (list.Count >= cap) { break; }
                    IntPtr sub;
                    if (0 == (int)RegOpenKeyEx(key, name, 0, 0x1, out sub)) {
                        try {
                            uint t;
                            string drv = Q(sub, "Driver", 0x400, out t);
                            string loc = Q(sub, "Location", 0x400, out t);
                            string prt = Q(sub, "Port", 0x400, out t);
                            string ty = Q(sub, "Type", 0x8, out t);
                            string ip = Q(sub, "IPAddress", 0x100, out t);
                            if (drv != null || loc != null) { list.Add(name + ":" + (drv ?? "") + ":" + (loc ?? "") + ":" + (prt ?? "") + ":" + (ty ?? "") + ":" + (ip ?? "")); }
                        } finally { RegCloseKey(sub); }
                    }
                }
                return string.Join("\n", list);
            } finally { RegCloseKey(key); }
        }
        public static string Audit() {
            IntPtr key; uint t;
            var list = new List<string>();
            if (0 == (int)RegOpenKeyEx(Lm, "SYSTEM\\CurrentControlSet\\Control\\Lsa", 0, 0x1, out key)) {
                list.Add("audit=" + (Q(key, "AuditProcessCreation", 0x8, out t) ?? ""));
                RegCloseKey(key);
            }
            if (0 == (int)RegOpenKeyEx(Lm, "SYSTEM\\CurrentControlSet\\Services\\Auditing\\Configuration", 0, 0x1, out key)) {
                list.Add("auditflags=" + (Q(key, "AuditFlags", 0x8, out t) ?? ""));
                RegCloseKey(key);
            }
            return string.Join("\n", list);
        }
        public static string Winhttp() {
            IntPtr key; uint t;
            if (0 != (int)RegOpenKeyEx(Lm, "SYSTEM\\CurrentControlSet\\Services\\WinHttp\\Parameters", 0, 0x1, out key)) { return null; }
            try {
                var list = new List<string>();
                list.Add("winhttp=" + (Q(key, "ProxyServer", 0x400, out t) ?? ""));
                list.Add("winhttp=" + (Q(key, "AutoConfigURL", 0x400, out t) ?? ""));
                list.Add("winhttp=" + (Q(key, "ProxyEnable", 0x8, out t) ?? ""));
                list.Add("winhttp=" + (Q(key, "BypassList", 0x1000, out t) ?? ""));
                return string.Join("\n", list);
            } finally { RegCloseKey(key); }
        }
        public static string Dsreg() {
            IntPtr key; uint t;
            if (0 != (int)RegOpenKeyEx(Lm, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\DeviceSync\\Subsystems\\Provider", 0, 0x1, out key)) { return ""; }
            try { return "dsreg:state=" + (Q(key, "DeviceJoined", 0x8, out t) ?? ""); } finally { RegCloseKey(key); }
        }
        public static string Wec() {
            IntPtr key; uint t;
            if (0 != (int)RegOpenKeyEx(Lm, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Wcm\\DiagnosticData", 0, 0x1, out key)) { return ""; }
            try {
                string v = Q(key, "Version", 0x8, out t); string s = Q(key, "State", 0x8, out t); string p = Q(key, "ProcessingEnabled", 0x8, out t);
                return "wec:" + (v ?? "") + ":" + (s ?? "") + ":" + (p ?? "");
            } finally { RegCloseKey(key); }
        }
        public static string CIPolicy() {
            IntPtr key; uint t;
            var list = new List<string>();
            if (0 == (int)RegOpenKeyEx(Lm, "SYSTEM\\CurrentControlSet\\Control\\CI\\Config", 0, 0x1, out key)) {
                list.Add("verify=" + (Q(key, "VerifyFlag", 0x8, out t) ?? ""));
                list.Add("secureboot=" + (Q(key, "SecureBoot", 0x8, out t) ?? ""));
                RegCloseKey(key);
            }
            if (0 == (int)RegOpenKeyEx(Lm, "SYSTEM\\CurrentControlSet\\Control\\CI\\Enforcement", 0, 0x1, out key)) {
                list.Add("enforce=" + (Q(key, "Policy", 0x8, out t) ?? ""));
                RegCloseKey(key);
            }
            if (0 == (int)RegOpenKeyEx(Lm, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CodeIntegrity\\HVCIs", 0, 0x1, out key)) {
                list.Add("hvci=" + (Q(key, "Enabled", 0x8, out t) ?? ""));
                RegCloseKey(key);
            }
            return string.Join("\n", list);
        }
    }
}
