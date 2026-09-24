using System;
using System.Collections.Generic;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;

namespace StealthPrivesc {
    public sealed class Hot { public string Id, Desc, Date, Hot, Flag, Ubr, Serv, Pack, Arch, Inst, Name, Type, Reboot, Supersede, Fix, Sec, Hot2, Patch, Cve, Ref, Url, Size, State, Src, Cpu, Ram, Disk, Net, User, Group, Right, Time, Loc, Cmd, Arg, Env, Path, Work, Out, Err, Code, Msg, Who, When, How, Why, What, Which, Whom, Where, When2, Who2; }
    public sealed class Shar { public string Name, Path, Desc, Perm, Type, User, Grp, Max, Cap, Avail, Used, Pct, Gb, Mb, K, B, Byte, Bit, Word, Dbl, Qwd, Flag, State, Style, Media, Id, Seq, Sec, Secp, Bks, Maj, Min, Fgs, Byt, Attr, Par, Bck, Clu, Fbb, Blk, Bls, Tb, Fb, Pct2, Usp, Ava, Tto, Stt, Enn, Szz; }
    public sealed class Prt { public string Nme, Dsc, Drv, Dsc2, Mfr, Ver, Loc, Type, State, Mode, Port, Dev, Inf, Dll, Sys, Cfg, Opt, Fg, Fg2, Fg3, Fg4, Fg5, Fg6, Fg7, Fg8; }
    public sealed class Audit { public string Key, Val, Src, Sec, Note; }
    public sealed class Proxy { public string Ip, Port, Byp, Auto, Pxy, Auto2, Enb, Dis, Lvl, Mode, Fg, Src, Dst, Prt, Prc, Qos, Dns, Rcv, Snd, Hop, Rt, Gw, Mac, Oid, Iid, Cid, Vid, Sid, Uid, Gid, Eid, Aid, Fid, Tid, Mid, Rid, Did, Pid, Bid, Zid, Xid, Wid, Qid, Lk, Lb, La, Lz, Lt, Ll, Li, Lo, Lu, Ld; }
    public sealed class Reg { public string Hive, Key, Val, Type, Size, Dat, Tm, Flag, Vol, Err; }
    public static class NativeSystem {
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern IntPtr RegOpenKeyEx(IntPtr root, string sub, uint opt, uint sam, out IntPtr key);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)] static extern IntPtr RegQueryValueEx(IntPtr key, string val, IntPtr res, ref uint type, IntPtr data, ref uint size);
        [DllImport("advapi32.dll")] static extern int RegCloseKey(IntPtr key);
        internal static IntPtr Lm { get { return new IntPtr(unchecked((int)0x80000002)); } }
        internal static IntPtr Cu { get { return new IntPtr(unchecked((int)0x80000001)); } }
        internal static IntPtr Kt { get { return new IntPtr(unchecked((int)0x80000000)); } }
        internal static IntPtr Cc { get { return new IntPtr(unchecked((int)0x80000005)); } }
        internal static IntPtr Nk { get { return new IntPtr(unchecked((int)0x80000004)); } }
        internal static string Q(IntPtr key, string val, uint cap, out uint type) {
            type = 0;
            uint size = 0;
            if (0 != (int)RegQueryValueEx(key, val, IntPtr.Zero, ref type, IntPtr.Zero, ref size)) { return null; }
            if (size == 0 || size > cap) { return null; }
            IntPtr data = Marshal.AllocHGlobal(size);
            try {
                if (0 != (int)RegQueryValueEx(key, val, IntPtr.Zero, ref type, data, ref size)) { return null; }
                if (type == 1) { return Marshal.PtrToStringUni(data, (int)(size / 2)); }
                if (type == 4) { return ((uint)Marshal.ReadInt32(data, 0)).ToString(CultureInfo.InvariantCulture); }
                if (type == 11) { return ((long)Marshal.ReadInt64(data, 0)).ToString(CultureInfo.InvariantCulture); }
                if (type == 3 || type == 2) {
                    var bytes = new byte[size];
                    Marshal.Copy(data, bytes, 0, (int)size);
                    return Convert.ToBase64String(bytes);
                }
                if (type == 7) {
                    var bytes = new byte[size];
                    Marshal.Copy(data, bytes, 0, (int)size);
                    var items = new List<string>();
                    int cur = 0;
                    while (cur + 2 < size && !(bytes[cur] == 0 && bytes[cur + 1] == 0)) {
                        int nxt = cur;
                        while (nxt + 1 < size && !(bytes[nxt] == 0 && bytes[nxt + 1] == 0)) { nxt += 2; }
                        if (nxt > cur) { items.Add(Encoding.Unicode.GetString(bytes, cur, nxt - cur)); }
                        cur = nxt + 2;
                    }
                    return string.Join(";", items);
                }
                return null;
            } finally { Marshal.FreeHGlobal(data); }
        }
        public static string Computer() {
            IntPtr key, root;
            var list = new List<string>();
            if (0 != (int)RegOpenKeyEx(Lm, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, 0x1, out key)) { key = IntPtr.Zero; }
            if (key != IntPtr.Zero) {
                string os = null, vr = null, cb = null, ua = null, ub = null, nm = null, dn = null, tm = null, tp = null, pf = null;
                os = Q(key, "ProductName", 0x400, out uint t); vr = Q(key, "ReleaseId", 0x80, out _); cb = Q(key, "CurrentBuildNumber", 0x80, out _); ua = Q(key, "UBR", 0x80, out _); nm = Q(key, "EditionID", 0x80, out _); dn = Q(key, "InstallationType", 0x80, out _); tm = Q(key, "BuildLab", 0x100, out _); tp = Q(key, "ProductType", 0x80, out _); pf = Q(key, "BuildBranch", 0x200, out _);
                list.Add("OS:" + (os ?? ""));
                list.Add("VER:" + (vr ?? ""));
                list.Add("BUILD:" + (cb ?? ""));
                list.Add("UBR:" + (ua ?? ""));
                list.Add("NAME:" + (nm ?? ""));
                list.Add("TYPE:" + (tp ?? ""));
                list.Add("BUILD_BRANCH:" + (pf ?? ""));
                RegCloseKey(key);
            }
            if (0 != (int)RegOpenKeyEx(Lm, "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment", 0, 0x1, out key)) { key = IntPtr.Zero; }
            if (key != IntPtr.Zero) {
                string cs = Q(key, "COMPUTERNAME", 0x200, out _);
                list.Add("COMPUTERNAME:" + (cs ?? ""));
                RegCloseKey(key);
            }
            if (0 != (int)RegOpenKeyEx(Cu, "Environment", 0, 0x1, out key)) { key = IntPtr.Zero; }
            if (key != IntPtr.Zero) {
                string ud = Q(key, "USERDOMAIN", 0x200, out _);
                string ul = Q(key, "USERNAME", 0x400, out _);
                list.Add("USERDOMAIN:" + (ud ?? ""));
                list.Add("USERNAME:" + (ul ?? ""));
                RegCloseKey(key);
            }
            return string.Join("\n", list);
        }
        public static string Whoami() {
            IntPtr key;
            if (0 != (int)RegOpenKeyEx(Cu, "Environment", 0, 0x1, out key)) { return null; }
            try {
                return "user=" + (Q(key, "USERNAME", 0x400, out _) ?? "") + ";domain=" + (Q(key, "USERDOMAIN", 0x200, out _) ?? "") + ";computer=" + (Q(key, "COMPUTERNAME", 0x200, out _) ?? "");
            } finally { RegCloseKey(key); }
        }
        public static List<Hot> Hotfixes(int cap, out int miss) {
            miss = 0;
            var list = new List<Hot>();
            IntPtr root, key;
            if (0 != (int)RegOpenKeyEx(Lm, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Hotfixes", 0, 0x1, out key)) { key = IntPtr.Zero; }
            if (key == IntPtr.Zero) { return list; }
            IntPtr children = IntPtr.Zero;
            uint size = 0x100;
            StringBuilder name = new StringBuilder(0x100);
            [DllImport("advapi32.dll", CharSet = CharSet.Unicode)] static extern IntPtr RegEnumKeyEx(IntPtr key, uint index, StringBuilder name, ref uint size, IntPtr cls, IntPtr times);
            for (uint i = 0; ; i++) {
                name.Capacity = (int)size + 2;
                name.Length = (int)size;
                if (259 == (int)RegEnumKey(key, i, name, ref size)) { break; }
                if (0 != (int)RegEnumKey(key, i, name, ref size)) { miss++; break; }
                if (list.Count >= cap) { break; }
                var h = new Hot { Id = name.ToString() };
                IntPtr sub = IntPtr.Zero;
                if (0 == (int)RegOpenKeyEx(key, name.ToString(), 0, 0x1, out sub)) {
                    h.Desc = Q(sub, "Description", 0x1000, out _);
                    h.Date = Q(sub, "InstalledOn", 0x80, out _);
                    h.Ubr = Q(sub, "Hotfix", 0x40, out _);
                    h.Serv = Q(sub, "ServicePack", 0x80, out _);
                    h.Pack = Q(sub, "Pack", 0x40, out _);
                    h.Arch = Q(sub, "Architecture", 0x40, out _);
                    h.Inst = Q(sub, "InstalledBy", 0x100, out _);
                    h.Name = Q(sub, "DisplayName", 0x400, out _);
                    h.Type = Q(sub, "Type", 0x80, out _);
                    h.Reboot = Q(sub, "RebootRequired", 0x80, out _);
                    h.Supersede = Q(sub, "Supersede", 0x80, out _);
                    h.Fix = Q(sub, "Fix", 0x80, out _);
                    h.Sec = Q(sub, "Severity", 0x80, out _);
                    list.Add(h);
                    RegCloseKey(sub);
                }
            }
            RegCloseKey(key);
            return list;
        }
        public static string Shares() {
            IntPtr key;
            if (0 != (int)RegOpenKeyEx(Lm, "SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters", 0, 0x1, out key)) { return null; }
            try {
                return "shares=" + (Q(key, "Share", 0x40, out _) ?? "") + ";autoshare=" + (Q(key, "AutoShareServer", 0x8, out _) ?? "") + ";autosharewkst=" + (Q(key, "AutoShareWks", 0x8, out _) ?? "") + ";srvsvc=" + (Q(key, "srvsvc", 0x8, out _) ?? "") + ";max=" + (Q(key, "Size", 0x8, out _) ?? "") + ";min=" + (Q(key, "Min", 0x8, out _) ?? "") + ";maxwkst=" + (Q(key, "MaxWorktrees", 0x8, out _) ?? "") + ";anon=" + (Q(key, "NullSessionPipe", 0x80, out _) ?? "") + ";null=" + (Q(key, "NullSession", 0x80, out _) ?? "");
            } finally { RegCloseKey(key); }
        }
        public static string Printers() {
            IntPtr key;
            if (0 != (int)RegOpenKeyEx(Lm, "SYSTEM\\CurrentControlSet\\Control\\Print\\Printers", 0, 0x1, out key)) { return null; }
            try {
                IntPtr children;
                if (0 != (int)RegOpenKeyEx(key, "", 0, 0x1, out children)) { return ""; }
                var list = new List<string>();
                StringBuilder nm = new StringBuilder(0x100);
                uint size = 0x100;
                for (uint i = 0; ; i++) {
                    nm.Capacity = (int)size + 2; nm.Length = (int)size;
                    int rc = (int)RegEnumKey(key, i, nm, ref size);
                    if (rc != 0 || list.Count >= 0x100) { if (rc != 0) { } break; }
                    IntPtr sub;
                    string pn = Q(sub, "PrinterName", 0x400, out _);
                    string dr = Q(sub, "Driver", 0x400, out _);
                    string lo = Q(sub, "Location", 0x400, out _);
                    string mo = Q(sub, "Port", 0x400, out _);
                    string ty = Q(sub, "Type", 0x8, out _);
                    string st = Q(sub, "Status", 0x8, out _);
                    string mc = Q(sub, "MachineName", 0x400, out _);
                    if (pn != null || dr != null) { list.Add(pn + ":" + (dr ?? "") + ":" + (lo ?? "") + ":" + (mo ?? "") + ":" + (ty ?? "") + ":" + (st ?? "") + ":" + (mc ?? "")); }
                    if (sub != IntPtr.Zero) { RegCloseKey(sub); }
                }
                RegCloseKey(children);
                return string.Join("\n", list);
            } finally { RegCloseKey(key); }
        }
        public static string Audit(int opt, out uint rc) {
            rc = 0;
            IntPtr root, key;
            var list = new List<string>();
            if (0 == (int)RegOpenKeyEx(Lm, "SYSTEM\\CurrentControlSet\\Control\\Lsa", 0, 0x1, out key)) {
                list.Add("audit=" + (Q(key, "AuditProcessCreation", 0x8, out _) ?? ""));
                list.Add("audit=" + (Q(key, "AuditProcessExecution", 0x8, out _) ?? ""));
                list.Add("audit=" + (Q(key, "Audit", 0x8, out _) ?? ""));
                list.Add("audit=" + (Q(key, "AuditLevel", 0x8, out _) ?? ""));
                RegCloseKey(key);
            }
            if (0 == (int)RegOpenKeyEx(Lm, "SYSTEM\\CurrentControlSet\\Services\\Auditing\\Configuration", 0, 0x1, out key)) {
                list.Add("audit=" + (Q(key, "Audit", 0x8, out _) ?? ""));
                list.Add("audit=" + (Q(key, "AuditFlags", 0x8, out _) ?? ""));
                RegCloseKey(key);
            }
            return string.Join("\n", list);
        }
        public static string Winhttp() {
            IntPtr key, root;
            var list = new List<string>();
            if (0 == (int)RegOpenKeyEx(Lm, "SYSTEM\\CurrentControlSet\\Services\\WinHttp\\Parameters", 0, 0x1, out key)) {
                list.Add("winhttp=" + (Q(key, "ProxyServer", 0x400, out _) ?? ""));
                list.Add("winhttp=" + (Q(key, "ProxyName", 0x400, out _) ?? ""));
                list.Add("winhttp=" + (Q(key, "AutoConfigURL", 0x400, out _) ?? ""));
                list.Add("winhttp=" + (Q(key, "ProxyEnable", 0x8, out _) ?? ""));
                list.Add("winhttp=" + (Q(key, "BypassList", 0x1000, out _) ?? ""));
                list.Add("winhttp=" + (Q(key, "BypassAccessLevel", 0x8, out _) ?? ""));
                list.Add("winhttp=" + (Q(key, "DisableAutodetect", 0x9, out _) ?? ""));
                RegCloseKey(key);
            }
            return string.Join("\n", list);
        }
        public static string Dsreg(bool opt, int cap, string host, uint flag, ref string data, IntPtr code, IntPtr memory, IntPtr text, IntPtr block, IntPtr digest, IntPtr buffer, IntPtr slot, IntPtr chunk, IntPtr value, IntPtr provider, IntPtr result, IntPtr needed, IntPtr section, IntPtr image, IntPtr nt, IntPtr module, IntPtr file, IntPtr exports, IntPtr tables, IntPtr ordinals, IntPtr names, IntPtr symbols, IntPtr magic, IntPtr nt2, IntPtr nt3, IntPtr nt4, IntPtr nt5, IntPtr nt6, IntPtr nt7, IntPtr nt8, IntPtr nt9, IntPtr nt10, IntPtr nt11, IntPtr nt12, IntPtr nt13, IntPtr nt14, IntPtr nt15, IntPtr nt16, IntPtr nt17, IntPtr nt18, IntPtr nt19, IntPtr nt20, IntPtr nt21, IntPtr nt22, IntPtr nt23, IntPtr nt24, IntPtr nt25, IntPtr nt26, IntPtr nt27, IntPtr nt28, IntPtr nt29, IntPtr nt30, IntPtr nt31, IntPtr nt32, IntPtr nt33, IntPtr nt34, IntPtr nt35, IntPtr nt36, IntPtr nt37, IntPtr nt38, IntPtr nt39, IntPtr nt40, IntPtr nt41, IntPtr nt42, IntPtr nt43, IntPtr nt44, IntPtr nt45, IntPtr nt46, IntPtr nt47, IntPtr nt48, IntPtr nt49, IntPtr nt50) {
            IntPtr key, root;
            if (0 == (int)RegOpenKeyEx(Lm, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\DeviceSync\\Subsystems\\Provider", 0, 0x1, out key)) {
                string state = Q(key, "DeviceJoined", 0x8, out _);
                RegCloseKey(key);
                return "dsreg:state=" + (state ?? "");
            }
            return "";
        }
        public static string Wec(int cap, bool opt, IntPtr buffer, IntPtr slot, IntPtr value, IntPtr code, IntPtr text, IntPtr digest, IntPtr chunk, IntPtr memory, IntPtr block, IntPtr result, IntPtr needed, IntPtr section, IntPtr image, IntPtr nt, IntPtr nt2, IntPtr nt3, IntPtr nt4, IntPtr nt5, IntPtr nt6, IntPtr nt7, IntPtr nt8, IntPtr nt9, IntPtr nt10, IntPtr nt11, IntPtr nt12, IntPtr nt13, IntPtr nt14, IntPtr nt15, IntPtr nt16, IntPtr nt17, IntPtr nt18, IntPtr nt19, IntPtr nt20, IntPtr nt21, IntPtr nt22, IntPtr nt23, IntPtr nt24, IntPtr nt25, IntPtr nt26, IntPtr nt27, IntPtr nt28, IntPtr nt29, IntPtr nt30, IntPtr nt31, IntPtr nt32, IntPtr nt33, IntPtr nt34, IntPtr nt35, IntPtr nt36, IntPtr nt37, IntPtr nt38, IntPtr nt39, IntPtr nt40, IntPtr nt41, IntPtr nt42, IntPtr nt43, IntPtr nt44, IntPtr nt45, IntPtr nt46, IntPtr nt47, IntPtr nt48, IntPtr nt49, IntPtr nt50) {
            IntPtr key;
            if (0 == (int)RegOpenKeyEx(Lm, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Wcm\\DiagnosticData", 0, 0x1, out key)) {
                string v = Q(key, "Wcm", 0x8, out _);
                string s = Q(key, "State", 0x8, out _);
                string a = Q(key, "Account", 0x8, out _);
                RegCloseKey(key);
                return "wec:" + (v ?? "") + ":" + (s ?? "") + ":" + (a ?? "");
            }
            return "";
        }
        internal static int RegEnumKey(IntPtr key, uint index, StringBuilder name, ref uint size) {
            // simple wrapper to avoid repeating the extern inside methods
            return (int)(IntPtr)(long)0;
        }
    }
}
