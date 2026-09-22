using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace StealthPrivesc {
    public sealed class DesktopContext {
        public long WindowHandle; public uint ProcessId, ThreadId, IdleMilliseconds;
        public string WindowClass; public bool TitlePresent; public string Title = "[REDACTED]";
    }
    public sealed class RpcEndpoint {
        public Guid InterfaceId, ObjectId; public ushort MajorVersion, MinorVersion;
        public string Binding;
    }
    public sealed class CredentialExposure {
        public string Target, UserName; public uint Type, Persistence, SecretBytes;
        public bool SecretReturned; public string Value = "[REDACTED]";
    }
    public sealed class NativeQueryResult<T> {
        public T[] Items; public int Error; public bool Truncated;
    }
    public static class NativeInspection {
        [StructLayout(LayoutKind.Sequential)] struct LastInput { public uint Size, Tick; }
        [StructLayout(LayoutKind.Sequential)] struct RpcIfId { public Guid Uuid; public ushort Major, Minor; }
        [StructLayout(LayoutKind.Sequential)] struct Credential {
            public uint Flags, Type; public IntPtr Target, Comment; public long LastWritten;
            public uint BlobSize; public IntPtr Blob; public uint Persist, AttributeCount;
            public IntPtr Attributes, Alias, User;
        }
        [DllImport("user32.dll", SetLastError=true)] static extern bool GetLastInputInfo(ref LastInput input);
        [DllImport("user32.dll")] static extern IntPtr GetForegroundWindow();
        [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr window, out uint process);
        [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern int GetClassName(IntPtr window, StringBuilder name, int size);
        [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern int GetWindowTextLength(IntPtr window);
        [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool CredEnumerate(string filter, uint flags, out uint count, out IntPtr credentials);
        [DllImport("advapi32.dll")] static extern void CredFree(IntPtr buffer);
        [DllImport("shell32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr CommandLineToArgvW(string command,out int count);
        [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr pointer);
        [DllImport("Rpcrt4.dll")] static extern int RpcMgmtEpEltInqBegin(IntPtr binding, uint type, IntPtr id, uint version, IntPtr uuid, out IntPtr context);
        [DllImport("Rpcrt4.dll", CharSet=CharSet.Unicode)] static extern int RpcMgmtEpEltInqNext(IntPtr context, out RpcIfId id, out IntPtr binding, out Guid uuid, out IntPtr annotation);
        [DllImport("Rpcrt4.dll")] static extern int RpcMgmtEpEltInqDone(ref IntPtr context);
        [DllImport("Rpcrt4.dll", CharSet=CharSet.Unicode)] static extern int RpcBindingToStringBinding(IntPtr binding, out IntPtr text);
        [DllImport("Rpcrt4.dll")] static extern int RpcBindingFree(ref IntPtr binding);
        [DllImport("Rpcrt4.dll", CharSet=CharSet.Unicode)] static extern int RpcStringFree(ref IntPtr text);

        public static DesktopContext Desktop() {
            LastInput input = new LastInput { Size=(uint)Marshal.SizeOf(typeof(LastInput)) };
            if(!GetLastInputInfo(ref input)) throw new Win32Exception(Marshal.GetLastWin32Error());
            IntPtr window=GetForegroundWindow(); uint pid; uint tid=GetWindowThreadProcessId(window,out pid);
            var name=new StringBuilder(256); GetClassName(window,name,name.Capacity);
            return new DesktopContext { WindowHandle=window.ToInt64(),ProcessId=pid,ThreadId=tid,
                WindowClass=name.ToString(),TitlePresent=GetWindowTextLength(window)>0,
                IdleMilliseconds=unchecked((uint)Environment.TickCount-input.Tick) };
        }
        public static string[] CommandArguments(string command) {
            int count;IntPtr buffer=CommandLineToArgvW(command,out count);
            if(buffer==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error());
            try{var result=new string[count];for(int i=0;i<count;i++)result[i]=Marshal.PtrToStringUni(Marshal.ReadIntPtr(buffer,i*IntPtr.Size));return result;}
            finally{LocalFree(buffer);}
        }
        public static NativeQueryResult<CredentialExposure> Credentials(int maximum) {
            uint count; IntPtr buffer;
            if(!CredEnumerate(null,0,out count,out buffer)) {
                int error=Marshal.GetLastWin32Error();
                return new NativeQueryResult<CredentialExposure> { Items=new CredentialExposure[0], Error=error==1168?0:error };
            }
            try {
                var result=new List<CredentialExposure>();
                for(int i=0;i<count;i++) {
                    var c=(Credential)Marshal.PtrToStructure(Marshal.ReadIntPtr(buffer,i*IntPtr.Size),typeof(Credential));
                    if(i<maximum) result.Add(new CredentialExposure { Target=Marshal.PtrToStringUni(c.Target),
                        UserName=Marshal.PtrToStringUni(c.User),Type=c.Type,Persistence=c.Persist,
                        SecretBytes=c.BlobSize,SecretReturned=c.Blob!=IntPtr.Zero && c.BlobSize>0 });
                    // Never marshal secret data to a managed string; erase each returned blob before freeing.
                    if(c.Blob!=IntPtr.Zero) for(uint j=0;j<c.BlobSize;j++) Marshal.WriteByte(c.Blob,(int)j,0);
                }
                return new NativeQueryResult<CredentialExposure> { Items=result.ToArray(),Truncated=count>maximum };
            } finally { CredFree(buffer); }
        }
        public static NativeQueryResult<RpcEndpoint> Endpoints(int maximum) {
            IntPtr context; int status=RpcMgmtEpEltInqBegin(IntPtr.Zero,0,IntPtr.Zero,0,IntPtr.Zero,out context);
            if(status!=0) return new NativeQueryResult<RpcEndpoint> { Items=new RpcEndpoint[0],Error=status };
            var result=new List<RpcEndpoint>();
            try {
                while(result.Count<=maximum) {
                    RpcIfId id; Guid uuid; IntPtr binding,annotation;
                    status=RpcMgmtEpEltInqNext(context,out id,out binding,out uuid,out annotation);
                    if(status==1772) break; // RPC_X_NO_MORE_ENTRIES
                    if(status!=0) return new NativeQueryResult<RpcEndpoint>{Items=result.ToArray(),Error=status};
                    try {
                        IntPtr text; status=RpcBindingToStringBinding(binding,out text);
                        if(status!=0) return new NativeQueryResult<RpcEndpoint>{Items=result.ToArray(),Error=status};
                        try { result.Add(new RpcEndpoint { InterfaceId=id.Uuid,MajorVersion=id.Major,MinorVersion=id.Minor,ObjectId=uuid,Binding=Marshal.PtrToStringUni(text) }); }
                        finally { RpcStringFree(ref text); }
                    } finally { if(binding!=IntPtr.Zero)RpcBindingFree(ref binding);if(annotation!=IntPtr.Zero)RpcStringFree(ref annotation); }
                }
                bool truncated=result.Count>maximum;if(truncated)result.RemoveAt(result.Count-1);
                return new NativeQueryResult<RpcEndpoint>{Items=result.ToArray(),Truncated=truncated};
            } finally { RpcMgmtEpEltInqDone(ref context); }
        }
    }
}
