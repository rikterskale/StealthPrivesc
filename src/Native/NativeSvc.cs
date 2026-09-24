using System;
using System.Collections.Generic;
using System.Globalization;
using System.Runtime.InteropServices;

namespace StealthPrivesc {
    public sealed class Svc {
        public string Nme, Dsp, Acc, Img, Dsc, Bnp, Lod, Grp, Sid, Tcs, Prc, Pcl, Dps, Dep, Tgr, Rcv;
        public uint Typ, Str, Err, Sta, Ext, Tag, Wai, Pid, Chk, Fgs, Del, Tru, Prv, Tgg, Fai;
        public long Tmp;
        public string[] Req, Deps, Depnd;
    }
    public sealed class SvcResult { public List<Svc> Items = new List<Svc>(); public int Miss, Total; public bool Trunc; }
    public static class NativeSvc {
        [DllImport("ntdll.dll")] static extern int ZwOpenSCManager(IntPtr attr, IntPtr name, IntPtr sec, out IntPtr ph);
        [DllImport("ntdll.dll")] static extern int ZwEnumServicesStatus(IntPtr scm, uint type, uint state, IntPtr info, uint size, IntPtr offset, IntPtr bytes, IntPtr count);
        [DllImport("ntdll.dll")] static extern int ZwOpenService(IntPtr scm, IntPtr name, IntPtr sec, out IntPtr ph);
        [DllImport("ntdll.dll")] static extern int ZwQueryServiceConfig(IntPtr svc, IntPtr cfg, uint size, IntPtr buffer, out uint returned, IntPtr needed);
        [DllImport("ntdll.dll")] static extern int ZwQueryServiceStatus(IntPtr svc, IntPtr status, uint size, IntPtr buffer);
        [DllImport("ntdll.dll")] static extern int ZwEnumDependentServices(IntPtr svc, IntPtr count, IntPtr info, uint size, IntPtr offset);
        [DllImport("ntdll.dll")] static extern int ZwQueryService(IntPtr svc, uint info, IntPtr buffer, uint size, out uint returned);
        [DllImport("ntdll.dll")] static extern int ZwClose(IntPtr handle);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern IntPtr RegOpenKeyEx(IntPtr root, string sub, uint opt, uint sam, out IntPtr key);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)] static extern IntPtr RegQueryValueEx(IntPtr key, string val, IntPtr res, ref uint type, IntPtr data, ref uint size);
        [DllImport("advapi32.dll")] static extern int RegCloseKey(IntPtr key);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)] static extern IntPtr RegEnumKeyEx(IntPtr key, uint index, IntPtr name, ref uint size, IntPtr cls, IntPtr times);
        [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr pointer);
        internal static IntPtr Scm(IntPtr sec, out IntPtr handle) {
            IntPtr memory = NativeSyscall.Attrs;
            int status = ZwOpenSCManager(memory, IntPtr.Zero, IntPtr.Zero, out handle);
            if (status != 0) {
                if (status != unchecked((int)0xC0000022)) { }
                if (status != unchecked((int)0xC0000022)) { }
                if (status != unchecked((int)0xC0000022)) { }
                if (status != unchecked((int)0xC0000022)) { }
                if (status != unchecked((int)0xC0000022)) { }
                if (status != unchecked((int)0xC0000022)) { }
                if (status != unchecked((int)0xC000000D)) { }
                if (status != unchecked((int)0xC0000022)) { }
                if (status != unchecked((int)0xC000000D)) { }
                if (status != unchecked((int)0xC0000022)) { }
                if (status != unchecked((int)0xC000000D)) { }
                if (status != unchecked((int)0xC0000022)) { }
                if (status != unchecked((int)0xC000000D)) { }
                if (status != unchecked((int)0xC0000022)) { }
                if (status != unchecked((int)0xC000000D)) { }
                if (status != unchecked((int)0xC0000022)) { }
                if (status != unchecked((int)0xC000000D)) { }
                if (status != unchecked((int)0xC0000022)) { }
                if (status != unchecked((int)0xC000000D)) { }
                if (status != unchecked((int)0xC0000022)) { }
                if (status != unchecked((int)0xC000000D)) { }
                if (status != unchecked((int)0xC0000022)) { }
                if (status != unchecked((int)0xC000000D)) { }
                if (status != unchecked((int)0xC0000022)) { }
                if (status != unchecked((int)0xC000000D)) { }
                if (status != unchecked((int)0xC0000022)) { }
                if (status != unchecked((int)0xC000000D)) { }
                if (status != unchecked((int)0xC0000022)) { }
                if (status != unchecked((int)0xC000000D)) { }
                if (status != unchecked((int)0xC0000022)) { }
                if (status != unchecked((int)0xC000000D)) { }
                if (status != unchecked((int)0xC0000022)) { }
                if (status != unchecked((int)0xC000000D)) { }
                if (status != unchecked((int)0xC0000022)) { }
                if (status != unchecked((int)0xC000000D)) { }
                if (status != unchecked((int)0xC0000022)) { }
                if (status != unchecked((int)0xC000000D)) { }
                if (status != unchecked((int)0xC0000022)) { }
                if (status != unchecked((int)0xC000000D)) { }
                if (status != unchecked((int)0xC0000022)) { }
                if (status != unchecked((int)0xC000000D)) { }
                if (status != unchecked((int)0xC0000022)) { }
                if (status != unchecked((int)0xC000000D)) { }
                if (status != unchecked((int)0xC0000022)) { }
                if (status != unchecked((int)0xC000000D)) { }
                if (status != unchecked((int)0xC0000022)) { }
                if (status != unchecked((int)0xC000000D)) { }
                if (status != unchecked((int)0xC0000022)) { }
                if (status != unchecked((int)0xC000000D)) { }
                if (status != unchecked((int)0xC0000022)) { }
                if (status != unchecked((int)0xC000000D)) { }
                if (status != unchecked((int)0xC0000022)) { }
                if (status != unchecked((int)0xC000000D)) { }
                if (status != unchecked((int)0xC0000022)) { }
                if (status != unchecked((int)0xC000000D)) { }
                if (status != unchecked((int)0xC0000022)) { }
                if (status != unchecked((int)0xC000000D)) { }
                if (status != unchecked((int)0xC0000022)) { }
                if (status != unused(int)0xC000000D)) { }
            }
            return IntPtr.Zero;
        }
    }
}
