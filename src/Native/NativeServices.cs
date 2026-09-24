using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
namespace StealthPrivesc {
    public sealed class RecoverySettings { public string Command; public uint ResetSeconds; public uint[] ActionTypes,Delays; public bool NonCrashFailures; }
    public static class NativeServices {
        [StructLayout(LayoutKind.Sequential)] struct Failure { public uint Reset;public IntPtr Reboot,Command;public uint Count;public IntPtr Actions; }
        [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr OpenSCManager(string machine,string database,uint access);
        [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr OpenService(IntPtr manager,string name,uint access);
        [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool QueryServiceConfig2(IntPtr service,uint level,IntPtr buffer,uint size,out uint needed);
        [DllImport("advapi32.dll")] static extern bool CloseServiceHandle(IntPtr handle);
        public static RecoverySettings Recovery(string name){
            IntPtr manager=OpenSCManager(null,null,1);if(manager==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error());
            IntPtr service=IntPtr.Zero,buffer=IntPtr.Zero;
            try{service=OpenService(manager,name,1);if(service==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error());
                uint size;QueryServiceConfig2(service,2,IntPtr.Zero,0,out size);if(size==0||size>1048576)throw new InvalidOperationException("Invalid recovery configuration size.");
                buffer=Marshal.AllocHGlobal((int)size);if(!QueryServiceConfig2(service,2,buffer,size,out size))throw new Win32Exception(Marshal.GetLastWin32Error());
                var data=(Failure)Marshal.PtrToStructure(buffer,typeof(Failure));if(data.Count>1024)throw new InvalidOperationException("Too many recovery actions.");
                var result=new RecoverySettings{Command=Marshal.PtrToStringUni(data.Command),ResetSeconds=data.Reset,ActionTypes=new uint[data.Count],Delays=new uint[data.Count]};
                for(int i=0;i<data.Count;i++){result.ActionTypes[i]=(uint)Marshal.ReadInt32(data.Actions,i*8);result.Delays[i]=(uint)Marshal.ReadInt32(data.Actions,i*8+4);}
                uint needed;if(!QueryServiceConfig2(service,4,buffer,size,out needed))throw new Win32Exception(Marshal.GetLastWin32Error());result.NonCrashFailures=Marshal.ReadInt32(buffer)!=0;return result;
            }finally{if(buffer!=IntPtr.Zero)Marshal.FreeHGlobal(buffer);if(service!=IntPtr.Zero)CloseServiceHandle(service);CloseServiceHandle(manager);}
        }
    }
}
