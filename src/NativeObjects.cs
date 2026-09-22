using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace StealthPrivesc {
    public sealed class PipeSecurity {
        public string Name; public byte[] Descriptor; public uint ServerProcessId;
        public int OpenError, SecurityError, ServerError;
    }
    public sealed class NamespaceEntry { public string Name, Type; }
    public sealed class NamespaceResult { public NamespaceEntry[] Entries; public uint Status; public bool Truncated; }
    public sealed class ObjectDescriptor { public byte[] Descriptor; public uint Status; }
    public static class NativeObjects {
        [StructLayout(LayoutKind.Sequential)] struct UnicodeString { public ushort Length, MaximumLength; public IntPtr Buffer; }
        [StructLayout(LayoutKind.Sequential)] struct ObjectAttributes {
            public int Length; public IntPtr Root, Name; public uint Attributes; public IntPtr SecurityDescriptor, QualityOfService;
        }
        [StructLayout(LayoutKind.Sequential)] struct DirectoryInfo { public UnicodeString Name, Type; }
        [StructLayout(LayoutKind.Sequential)] struct IoStatus { public IntPtr Status, Information; }
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetNamedPipeServerProcessId(SafeFileHandle pipe,out uint pid);
        [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetKernelObjectSecurity(SafeFileHandle handle, uint info, byte[] buffer, uint length, out uint needed);
        [DllImport("ntdll.dll")] static extern uint NtOpenDirectoryObject(out IntPtr handle,uint access,ref ObjectAttributes attributes);
        [DllImport("ntdll.dll")] static extern uint NtQueryDirectoryObject(IntPtr directory,IntPtr buffer,uint length,bool single,bool restart,ref uint context,out uint needed);
        [DllImport("ntdll.dll")] static extern uint NtQuerySecurityObject(IntPtr handle,uint info,byte[] buffer,uint length,out uint needed);
        [DllImport("ntdll.dll")] static extern uint NtOpenFile(out IntPtr handle,uint access,ref ObjectAttributes attributes,out IoStatus status,uint share,uint options);
        [DllImport("ntdll.dll")] static extern uint NtClose(IntPtr handle);
        static ObjectAttributes Attributes(string name,out IntPtr stringMemory,out IntPtr nameMemory) {
            nameMemory=Marshal.StringToHGlobalUni(name);
            var text=new UnicodeString { Length=checked((ushort)(name.Length*2)),MaximumLength=checked((ushort)((name.Length+1)*2)),Buffer=nameMemory };
            stringMemory=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UnicodeString)));Marshal.StructureToPtr(text,stringMemory,false);
            return new ObjectAttributes { Length=Marshal.SizeOf(typeof(ObjectAttributes)),Name=stringMemory,Attributes=0x40 };
        }
        public static PipeSecurity InspectPipe(string name) {
            var result=new PipeSecurity { Name=name };
            // READ_CONTROL + READ_ATTRIBUTES, SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION.
            using(var handle=CreateFile(name,0x20080,3,IntPtr.Zero,3,0x110000,IntPtr.Zero)) {
                if(handle.IsInvalid){result.OpenError=Marshal.GetLastWin32Error();return result;}
                uint needed; GetKernelObjectSecurity(handle,7,null,0,out needed);
                if(needed>0 && needed<1048576) {
                    var descriptor=new byte[needed];
                    if(GetKernelObjectSecurity(handle,7,descriptor,needed,out needed)) result.Descriptor=descriptor;
                    else result.SecurityError=Marshal.GetLastWin32Error();
                } else result.SecurityError=Marshal.GetLastWin32Error();
                uint pid;if(GetNamedPipeServerProcessId(handle,out pid)) result.ServerProcessId=pid;
                else result.ServerError=Marshal.GetLastWin32Error();
            }
            return result;
        }
        public static NamespaceResult Directory(string path,int maximum) {
            IntPtr text,name;var attributes=Attributes(path,out text,out name);IntPtr handle;
            uint status;
            try{status=NtOpenDirectoryObject(out handle,1,ref attributes);}finally{Marshal.FreeHGlobal(text);Marshal.FreeHGlobal(name);}
            if(status!=0)return new NamespaceResult { Entries=new NamespaceEntry[0],Status=status };
            IntPtr buffer=Marshal.AllocHGlobal(65536);var entries=new List<NamespaceEntry>();
            try {
                uint context=0,needed;
                while(entries.Count<=maximum) {
                    status=NtQueryDirectoryObject(handle,buffer,65536,true,entries.Count==0,ref context,out needed);
                    if(status==0x8000001a){status=0;break;}
                    if(status!=0)break;
                    var entry=(DirectoryInfo)Marshal.PtrToStructure(buffer,typeof(DirectoryInfo));
                    entries.Add(new NamespaceEntry { Name=Marshal.PtrToStringUni(entry.Name.Buffer,entry.Name.Length/2),Type=Marshal.PtrToStringUni(entry.Type.Buffer,entry.Type.Length/2) });
                }
                bool truncated=entries.Count>maximum;if(truncated)entries.RemoveAt(entries.Count-1);
                return new NamespaceResult {Entries=entries.ToArray(),Status=status,Truncated=truncated};
            }finally{Marshal.FreeHGlobal(buffer);NtClose(handle);}
        }
        public static ObjectDescriptor Security(string path,bool directory) {
            IntPtr text,name;var attributes=Attributes(path,out text,out name);IntPtr handle;uint status;
            try {
                if(directory)status=NtOpenDirectoryObject(out handle,0x20000,ref attributes);
                else {IoStatus io;status=NtOpenFile(out handle,0x20000,ref attributes,out io,7,0x40);}
            }finally{Marshal.FreeHGlobal(text);Marshal.FreeHGlobal(name);}
            if(status!=0)return new ObjectDescriptor {Status=status};
            try {
                uint needed;NtQuerySecurityObject(handle,7,null,0,out needed);
                if(needed==0 || needed>1048576)return new ObjectDescriptor {Status=0xc000000d};
                var bytes=new byte[needed];status=NtQuerySecurityObject(handle,7,bytes,needed,out needed);
                return new ObjectDescriptor {Descriptor=status==0?bytes:null,Status=status};
            }finally{NtClose(handle);}
        }
    }
}
