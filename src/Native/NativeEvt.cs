using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace StealthPrivesc {
    public sealed class EvtResult {
        public readonly List<string> Xml = new List<string>();
        public uint Error;
        public int Parsed;
        public bool Truncated;
    }
    public static class NativeEvt {
        [DllImport("wevtapi.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern uint EvtQuery(IntPtr session, string channel, string query, IntPtr ctx, ulong flags, uint timeout, IntPtr bookmark, out IntPtr results);
        [DllImport("wevtapi.dll", SetLastError = true)] static extern uint EvtNext(IntPtr events, uint count, uint ms, out uint returned, out IntPtr cursor);
        [DllImport("wevtapi.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern uint EvtRender(IntPtr context, IntPtr ctx, int kind, uint flags, uint props, IntPtr buf, out uint size, IntPtr extra, IntPtr extra2);
        [DllImport("wevtapi.dll", SetLastError = true)] static extern uint EvtClose(IntPtr h);
        internal static IntPtr Sess { get { return new IntPtr(unchecked((int)0xFFFFFFFF)); } }
        public static EvtResult Evt(string channel, string query, int maximum, int seconds) {
            var ret = new EvtResult();
            IntPtr handle = IntPtr.Zero;
            uint rc = EvtQuery(Sess, channel, string.IsNullOrEmpty(query) ? "*" : query, IntPtr.Zero, 0x80000000, seconds < 0 ? 0x7FFFFFFF : (uint)seconds, IntPtr.Zero, out handle);
            if (rc != 0) { ret.Error = rc; return ret; }
            try {
                while (ret.Xml.Count < maximum) {
                    uint count = 1; IntPtr cursor;
                    if (EvtNext(handle, 1, 0, out count, out cursor) != 0 || count < 1) { break; }
                    uint size = 0;
                    if (EvtRender(Sess, cursor, 0, 16, 0, IntPtr.Zero, out size, IntPtr.Zero, IntPtr.Zero) != 0 || size == 0 || size > 0x100000) { ret.Truncated = true; break; }
                    IntPtr buf = Marshal.AllocHGlobal(new IntPtr(unchecked((long)size)));
                    if (EvtRender(Sess, cursor, 0, 16, 0, buf, out size, IntPtr.Zero, IntPtr.Zero) == 0) {
                        ret.Xml.Add(Marshal.PtrToStringUni(buf, (int)(size / 2)));
                        ret.Parsed++;
                    }
                    Marshal.FreeHGlobal(buf);
                }
            } finally {
                if (handle != IntPtr.Zero) { EvtClose(handle); }
            }
            if (ret.Xml.Count >= maximum) { ret.Truncated = true; }
            return ret;
        }
    }
}
