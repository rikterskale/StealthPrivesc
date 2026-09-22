using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace StealthPrivesc {
    public sealed class HandleEvidence {
        public uint SourceProcessId, TargetProcessId, GrantedAccess; public long HandleValue;
        public string ObjectType, TargetOwnerSid, Path; public byte[] Descriptor;
    }
    public sealed class HandleQuery { public HandleEvidence[] Items; public uint Status; public int InaccessibleSources, UnresolvedObjects; public bool Truncated; }
    public static class NativeHandles {
        [StructLayout(LayoutKind.Sequential)] struct Entry {
            public IntPtr Object, ProcessId, Handle; public uint Access;
            public ushort BackTrace, TypeIndex; public uint Attributes, Reserved;
        }
        [StructLayout(LayoutKind.Sequential)] struct UnicodeString { public ushort Length, MaximumLength; public IntPtr Buffer; }
        [DllImport("ntdll.dll")] static extern uint NtQuerySystemInformation(int kind,IntPtr buffer,int length,out int needed);
        [DllImport("ntdll.dll")] static extern uint NtQueryObject(IntPtr handle,int kind,IntPtr buffer,int length,out int needed);
        [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint access,bool inherit,uint pid);
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool DuplicateHandle(IntPtr source,IntPtr handle,IntPtr target,out IntPtr duplicate,uint access,bool inherit,uint options);
        [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll")] static extern uint GetProcessId(IntPtr process);
        [DllImport("kernel32.dll")] static extern uint GetProcessIdOfThread(IntPtr thread);
        [DllImport("kernel32.dll")] static extern uint GetFileType(IntPtr file);
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern uint GetFinalPathNameByHandle(IntPtr file,StringBuilder path,uint size,uint flags);
        [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr process,uint access,out IntPtr token);
        [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetKernelObjectSecurity(IntPtr handle,uint info,byte[] buffer,uint length,out uint needed);
        static string TypeName(IntPtr handle) {
            int needed;IntPtr buffer=Marshal.AllocHGlobal(4096);
            try {
                uint status=NtQueryObject(handle,2,buffer,4096,out needed);
                if(status!=0)return null;
                var text=(UnicodeString)Marshal.PtrToStructure(buffer,typeof(UnicodeString));
                return Marshal.PtrToStringUni(text.Buffer,text.Length/2);
            }finally{Marshal.FreeHGlobal(buffer);}
        }
        static string Owner(uint pid) {
            IntPtr process=OpenProcess(0x1000,false,pid);if(process==IntPtr.Zero)return null;
            try{IntPtr token;if(!OpenProcessToken(process,8,out token))return null;
                try{using(var identity=new WindowsIdentity(token))return identity.User.Value;}finally{CloseHandle(token);}
            }finally{CloseHandle(process);}
        }
        public static HandleQuery Inspect(int maximum,int maximumScan) {
            int size=1024*1024,needed;IntPtr buffer=IntPtr.Zero;uint status;
            var results=new List<HandleEvidence>();var sources=new Dictionary<uint,IntPtr>();
            var typeNames=new Dictionary<ushort,string>();int denied=0,unresolved=0;bool truncated=false;
            var clock=Stopwatch.StartNew();
            try{
                while(true){
                    buffer=Marshal.AllocHGlobal(size);status=NtQuerySystemInformation(64,buffer,size,out needed);
                    if(status!=0xc0000004)break;
                    Marshal.FreeHGlobal(buffer);buffer=IntPtr.Zero;
                    size=Math.Max(size*2,needed);
                    if(size>256*1024*1024)throw new InvalidOperationException("System handle table exceeds memory budget.");
                }
                if(status!=0)return new HandleQuery{Items=results.ToArray(),Status=status};
                long count=IntPtr.Size==8?Marshal.ReadInt64(buffer):Marshal.ReadInt32(buffer);
                int stride=Marshal.SizeOf(typeof(Entry));int offset=2*IntPtr.Size;
                if(count<0 || count>(size-offset)/stride)throw new InvalidOperationException("Invalid system handle table.");
                for(long i=0;i<count;i++){
                    if(i>=maximumScan || clock.Elapsed.TotalSeconds>20 || results.Count>=maximum){truncated=true;break;}
                    var entry=(Entry)Marshal.PtrToStructure(IntPtr.Add(buffer,checked(offset+(int)i*stride)),typeof(Entry));
                    if((entry.Access & 0xc007e)==0)continue;
                    uint pid=unchecked((uint)entry.ProcessId.ToInt64());IntPtr source;
                    if(!sources.TryGetValue(pid,out source)){
                        source=OpenProcess(0x40,false,pid);sources[pid]=source;
                        if(source==IntPtr.Zero)denied++;
                    }
                    if(source==IntPtr.Zero)continue;
                    IntPtr duplicate;if(!DuplicateHandle(source,entry.Handle,GetCurrentProcess(),out duplicate,0,false,2)){unresolved++;continue;}
                    try{
                        string type;if(!typeNames.TryGetValue(entry.TypeIndex,out type)){
                            type=TypeName(duplicate);if(type==null){unresolved++;continue;}typeNames[entry.TypeIndex]=type;
                        }
                        if(type!="Process" && type!="Thread" && type!="File")continue;
                        if(type=="Process" && (entry.Access&0xc006a)==0)continue;
                        if(type=="Thread" && (entry.Access&0xc0330)==0)continue;
                        var item=new HandleEvidence{SourceProcessId=pid,HandleValue=entry.Handle.ToInt64(),ObjectType=type,GrantedAccess=entry.Access};
                        if(type=="Process")item.TargetProcessId=GetProcessId(duplicate);
                        if(type=="Thread")item.TargetProcessId=GetProcessIdOfThread(duplicate);
                        if(type=="File"){
                            if(GetFileType(duplicate)!=1)continue; // Never resolve pipe/device names.
                            var path=new StringBuilder(32768);
                            uint length=GetFinalPathNameByHandle(duplicate,path,(uint)path.Capacity,0);
                            if(length==0 || length>=path.Capacity){unresolved++;continue;}
                            item.Path=path.ToString();uint required;
                            GetKernelObjectSecurity(duplicate,7,null,0,out required);
                            if(required>0 && required<1048576){var bytes=new byte[required];if(GetKernelObjectSecurity(duplicate,7,bytes,required,out required))item.Descriptor=bytes;}
                        }else{
                            if(item.TargetProcessId==0){unresolved++;continue;}
                            item.TargetOwnerSid=Owner(item.TargetProcessId);
                            if(item.TargetOwnerSid==null)unresolved++;
                        }
                        results.Add(item);
                    }finally{CloseHandle(duplicate);}
                }
                return new HandleQuery{Items=results.ToArray(),InaccessibleSources=denied,UnresolvedObjects=unresolved,Truncated=truncated};
            }finally{
                foreach(var source in sources.Values)if(source!=IntPtr.Zero)CloseHandle(source);
                if(buffer!=IntPtr.Zero)Marshal.FreeHGlobal(buffer);
            }
        }
    }
}
