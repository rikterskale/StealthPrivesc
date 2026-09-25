using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace StealthPrivesc {
    public sealed class Svc {
        public string Nme, Dsp, Img, Bnp, Acc, Gr, Dsc;
        public uint Typ, Str, Sta, Pid;
    }
    public sealed class SvcResult { public Svc[] Items = new Svc[0]; public int Total, Miss; public bool Trunc; }
    public static class NativeSvc {
        [DllImport("ntdll.dll")] static extern int ZwOpenSCManager(IntPtr attr, IntPtr name, IntPtr sec, out IntPtr ph);
        [DllImport("ntdll.dll")] static extern int ZwEnumServicesStatus(IntPtr scm, uint type, uint state, IntPtr info, uint size, IntPtr offset, IntPtr bytes, IntPtr count);
        [DllImport("ntdll.dll")] static extern int ZwOpenService(IntPtr scm, IntPtr name, IntPtr sec, out IntPtr ph);
        [DllImport("ntdll.dll")] static extern int ZwQueryService(IntPtr svc, uint info, IntPtr buffer, uint size, out uint returned);
        [DllImport("ntdll.dll")] static extern int ZwClose(IntPtr handle);
        [StructLayout(LayoutKind.Sequential)] public struct Ustr { public ushort Length, Max; public IntPtr Buffer; }
        [StructLayout(LayoutKind.Sequential)] struct SvcEnum { public Ustr Name, Display; public uint State, Type, Ctrl, Exit, Check, Wait, Pid, Tid; }
        [StructLayout(LayoutKind.Sequential)] struct SvcConf { public uint Type, Start, Ctrl; public Ustr Name, Binary, Image, Load, Tag; public uint Req; public Ustr Account, Gr; }
        internal static string U(Ustr s) { return (s.Buffer == IntPtr.Zero || s.Length == 0) ? null : Marshal.PtrToStringUni(s.Buffer, s.Length / 2); }
        public static SvcResult All(int maximum) {
            var result = new SvcResult();
            IntPtr scm;
            int open = ZwOpenSCManager(NativeSyscall.Attrs, IntPtr.Zero, IntPtr.Zero, out scm);
            if (open != 0) { result.Miss = open; return result; }
            IntPtr status = Marshal.AllocHGlobal(0x100);
            IntPtr conf = Marshal.AllocHGlobal(0x400);
            var found = new List<Svc>();
            try {
                for (uint offset = 0; ; ) {
                    if (found.Count >= maximum) { result.Trunc = true; break; }
                    int st = ZwEnumServicesStatus(scm, 0xFFFFFF, 0xFFFFFF, status, 0x100, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
                    if (st == 259) { break; }
                    if (st != 0) { result.Miss = st; break; }
                    var item = (SvcEnum)Marshal.PtrToStructure(status, typeof(SvcEnum));
                    var svc = new Svc { Nme = U(item.Name), Dsp = U(item.Display), Typ = item.Type, Sta = item.State, Pid = item.Pid };
                    IntPtr service;
                    if (ZwOpenService(scm, item.Name.Buffer, IntPtr.Zero, out service) == 0 && service != IntPtr.Zero) {
                        uint returned = 0;
                        if (ZwQueryService(service, 0, conf, 0x400, out returned) == 0) {
                            var cfg = (SvcConf)Marshal.PtrToStructure(conf, typeof(SvcConf));
                            svc.Img = U(cfg.Image); svc.Bnp = U(cfg.Binary); svc.Acc = U(cfg.Account); svc.Gr = U(cfg.Gr); svc.Str = cfg.Start;
                        }
                        ZwClose(service);
                    }
                    found.Add(svc);
                    result.Total++;
                }
                result.Items = found.ToArray();
                return result;
            } finally { ZwClose(scm); Marshal.FreeHGlobal(status); Marshal.FreeHGlobal(conf); }
        }
    }
}


