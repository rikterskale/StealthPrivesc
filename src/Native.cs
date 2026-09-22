using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace StealthPrivesc {
    // Query-only native interop. No privilege adjustment, service control or object mutation.
    public sealed class TokenSid { public string Sid; public uint Attributes; }
    public sealed class TokenPrivilege { public string Name; public uint Attributes; public bool Enabled; }
    public sealed class AccessResult { public bool Allowed; public int Error; }
    public static class Native {
        [StructLayout(LayoutKind.Sequential)] struct Luid { public uint Low; public int High; }
        [StructLayout(LayoutKind.Sequential)] struct LuidAttributes { public Luid Luid; public uint Attributes; }
        [StructLayout(LayoutKind.Sequential)] struct SidAttributes { public IntPtr Sid; public uint Attributes; }
        [StructLayout(LayoutKind.Sequential)] struct TokenGroups { public uint Count; public SidAttributes First; }
        [StructLayout(LayoutKind.Sequential)] struct Mapping { public uint Read, Write, Execute, All; }
        [StructLayout(LayoutKind.Sequential)] struct LsaString { public ushort Length, MaximumLength; public IntPtr Buffer; }
        [StructLayout(LayoutKind.Sequential)] struct LsaAttributes { public uint Length; public IntPtr RootDirectory, ObjectName; public uint Attributes; public IntPtr SecurityDescriptor, SecurityQualityOfService; }
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
        [DllImport("advapi32.dll", SetLastError=true)] static extern bool GetTokenInformation(IntPtr token, int kind, IntPtr buffer, int length, out int needed);
        [DllImport("advapi32.dll", SetLastError=true)] static extern bool DuplicateToken(IntPtr token, int level, out IntPtr duplicate);
        [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool LookupPrivilegeName(string system, ref Luid luid, StringBuilder name, ref int length);
        [DllImport("advapi32.dll", SetLastError=true)] static extern bool AccessCheck(byte[] descriptor, IntPtr token, uint access, ref Mapping mapping, IntPtr privileges, ref uint size, out uint granted, out bool allowed);
        [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr OpenSCManager(string machine, string database, uint access);
        [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr OpenService(IntPtr manager, string name, uint access);
        [DllImport("advapi32.dll", SetLastError=true)] static extern bool CloseServiceHandle(IntPtr handle);
        [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
        [DllImport("advapi32.dll")] static extern uint LsaOpenPolicy(IntPtr system, ref LsaAttributes attributes, uint access, out IntPtr policy);
        [DllImport("advapi32.dll")] static extern uint LsaEnumerateAccountRights(IntPtr policy, byte[] sid, out IntPtr rights, out uint count);
        [DllImport("advapi32.dll")] static extern uint LsaNtStatusToWinError(uint status);
        [DllImport("advapi32.dll")] static extern uint LsaFreeMemory(IntPtr memory);
        [DllImport("advapi32.dll")] static extern uint LsaClose(IntPtr policy);

        static IntPtr TokenBuffer(IntPtr token, int kind) {
            int size; GetTokenInformation(token, kind, IntPtr.Zero, 0, out size);
            if(size == 0) throw new Win32Exception(Marshal.GetLastWin32Error());
            IntPtr buffer = Marshal.AllocHGlobal(size);
            if(!GetTokenInformation(token, kind, buffer, size, out size)) { int e=Marshal.GetLastWin32Error(); Marshal.FreeHGlobal(buffer); throw new Win32Exception(e); }
            return buffer;
        }
        public static int TokenInteger(int kind) {
            using(WindowsIdentity identity=WindowsIdentity.GetCurrent()) {
                IntPtr p=TokenBuffer(identity.Token,kind);
                try { return Marshal.ReadInt32(p); } finally { Marshal.FreeHGlobal(p); }
            }
        }
        public static TokenSid[] Sids(int kind) {
            using(WindowsIdentity identity=WindowsIdentity.GetCurrent()) {
                IntPtr p=TokenBuffer(identity.Token,kind);
                try {
                    var result=new List<TokenSid>();
                    int count= kind==25 ? 1 : Marshal.ReadInt32(p);
                    int offset= kind==25 ? 0 : (int)Marshal.OffsetOf(typeof(TokenGroups),"First");
                    int stride=Marshal.SizeOf(typeof(SidAttributes));
                    for(int i=0;i<count;i++) {
                        var item=(SidAttributes)Marshal.PtrToStructure(IntPtr.Add(p,offset+i*stride),typeof(SidAttributes));
                        result.Add(new TokenSid { Sid=new SecurityIdentifier(item.Sid).Value, Attributes=item.Attributes });
                    }
                    return result.ToArray();
                } finally { Marshal.FreeHGlobal(p); }
            }
        }
        public static TokenPrivilege[] Privileges() {
            using(WindowsIdentity identity=WindowsIdentity.GetCurrent()) {
                IntPtr p=TokenBuffer(identity.Token,3);
                try {
                    var result=new List<TokenPrivilege>(); int count=Marshal.ReadInt32(p);
                    for(int i=0;i<count;i++) {
                        var item=(LuidAttributes)Marshal.PtrToStructure(IntPtr.Add(p,4+i*Marshal.SizeOf(typeof(LuidAttributes))),typeof(LuidAttributes));
                        int length=256; var name=new StringBuilder(length);
                        if(!LookupPrivilegeName(null,ref item.Luid,name,ref length)) throw new Win32Exception(Marshal.GetLastWin32Error());
                        result.Add(new TokenPrivilege { Name=name.ToString(), Attributes=item.Attributes, Enabled=(item.Attributes&2)!=0 });
                    }
                    return result.ToArray();
                } finally { Marshal.FreeHGlobal(p); }
            }
        }
        public static AccessResult CheckAccess(byte[] descriptor, uint desired, bool registry) {
            using(WindowsIdentity identity=WindowsIdentity.GetCurrent()) {
                IntPtr token;
                if(!DuplicateToken(identity.Token,2,out token)) throw new Win32Exception(Marshal.GetLastWin32Error());
                try {
                    Mapping map = registry ? new Mapping { Read=0x20019, Write=0x20006, Execute=0x20019, All=0xf003f } : new Mapping { Read=0x120089, Write=0x120116, Execute=0x1200a0, All=0x1f01ff };
                    uint size=1024, granted; bool allowed; IntPtr buffer=Marshal.AllocHGlobal((int)size);
                    try {
                        bool ok=AccessCheck(descriptor,token,desired,ref map,buffer,ref size,out granted,out allowed);
                        int error=ok?0:Marshal.GetLastWin32Error();
                        if(!ok && error==122) {
                            buffer=Marshal.ReAllocHGlobal(buffer,(IntPtr)size);
                            ok=AccessCheck(descriptor,token,desired,ref map,buffer,ref size,out granted,out allowed);
                            error=ok?0:Marshal.GetLastWin32Error();
                        }
                        return new AccessResult { Allowed=ok && allowed, Error=error };
                    } finally { Marshal.FreeHGlobal(buffer); }
                } finally { CloseHandle(token); }
            }
        }
        public static AccessResult ServiceAccess(string name, uint access) {
            if(String.IsNullOrEmpty(name)) name=null;
            IntPtr manager=OpenSCManager(null,null,name==null?access:1);
            if(manager==IntPtr.Zero) return new AccessResult { Error=Marshal.GetLastWin32Error() };
            try {
                if(name==null) return new AccessResult { Allowed=true };
                IntPtr service=OpenService(manager,name,access);
                if(service==IntPtr.Zero) return new AccessResult { Error=Marshal.GetLastWin32Error() };
                CloseServiceHandle(service); return new AccessResult { Allowed=true };
            } finally { CloseServiceHandle(manager); }
        }
        public static AccessResult ProcessAccess(uint pid, uint access) {
            IntPtr process=OpenProcess(access,false,pid);
            if(process==IntPtr.Zero) return new AccessResult { Error=Marshal.GetLastWin32Error() };
            CloseHandle(process); return new AccessResult { Allowed=true };
        }
        public static string[] AccountRights(string sidText) {
            var attributes=new LsaAttributes(); attributes.Length=(uint)Marshal.SizeOf(typeof(LsaAttributes));
            IntPtr policy; uint status=LsaOpenPolicy(IntPtr.Zero,ref attributes,0x800,out policy);
            if(status!=0) throw new Win32Exception((int)LsaNtStatusToWinError(status));
            try {
                var sid=new SecurityIdentifier(sidText); var data=new byte[sid.BinaryLength]; sid.GetBinaryForm(data,0);
                IntPtr buffer; uint count; status=LsaEnumerateAccountRights(policy,data,out buffer,out count);
                if(status==0xc0000034) return new string[0];
                if(status!=0) throw new Win32Exception((int)LsaNtStatusToWinError(status));
                try {
                    var result=new List<string>(); int stride=Marshal.SizeOf(typeof(LsaString));
                    for(int i=0;i<count;i++) { var s=(LsaString)Marshal.PtrToStructure(IntPtr.Add(buffer,i*stride),typeof(LsaString)); result.Add(Marshal.PtrToStringUni(s.Buffer,s.Length/2)); }
                    return result.ToArray();
                } finally { LsaFreeMemory(buffer); }
            } finally { LsaClose(policy); }
        }
    }
}
