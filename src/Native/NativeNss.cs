using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
namespace StealthPrivesc {
    public sealed class NssProbe {public int Status;public bool Recovered;public string Value="[REDACTED]";}
    public static class NativeNss {
        [StructLayout(LayoutKind.Sequential)] struct Item {public uint Type;public IntPtr Data;public uint Length;}
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate int Initialize(byte[] directory,byte[] certPrefix,byte[] keyPrefix,byte[] module,uint flags);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate int Shutdown();
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate int Decrypt(ref Item input,ref Item output,IntPtr context);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate void FreeItem(ref Item item,int freeItem);
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr LoadLibraryEx(string file,IntPtr reserved,uint flags);
        [DllImport("kernel32.dll",CharSet=CharSet.Ansi,ExactSpelling=true,SetLastError=true)] static extern IntPtr GetProcAddress(IntPtr library,string name);
        [DllImport("kernel32.dll")] static extern bool FreeLibrary(IntPtr library);
        static Delegate Function(IntPtr library,string name,Type type){IntPtr address=GetProcAddress(library,name);if(address==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error());return Marshal.GetDelegateForFunctionPointer(address,type);}
        public static NssProbe[] Inspect(string libraryPath,string profile,string[] encrypted){
            IntPtr library=LoadLibraryEx(libraryPath,IntPtr.Zero,0x900);if(library==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error());bool initialized=false;Shutdown shutdown=null;
            try{
                var init=(Initialize)Function(library,"NSS_Initialize",typeof(Initialize));shutdown=(Shutdown)Function(library,"NSS_Shutdown",typeof(Shutdown));var decrypt=(Decrypt)Function(library,"PK11SDR_Decrypt",typeof(Decrypt));var free=(FreeItem)Function(library,"SECITEM_ZfreeItem",typeof(FreeItem));
                // Read-only databases; do not load profile-specified PKCS#11 modules or roots.
                int status=init(Encoding.UTF8.GetBytes("sql:"+profile+"\0"),new byte[]{0},new byte[]{0},new byte[]{0},1|4|16);if(status!=0)throw new InvalidOperationException("NSS read-only initialization failed.");initialized=true;
                var results=new NssProbe[encrypted.Length];
                for(int i=0;i<encrypted.Length;i++){
                    var bytes=Convert.FromBase64String(encrypted[i]);var input=new Item{Length=(uint)bytes.Length,Data=Marshal.AllocHGlobal(bytes.Length)};var output=new Item();
                    try{Marshal.Copy(bytes,0,input.Data,bytes.Length);status=decrypt(ref input,ref output,IntPtr.Zero);results[i]=new NssProbe{Status=status,Recovered=status==0&&output.Length>0};}
                    finally{if(output.Data!=IntPtr.Zero)free(ref output,0);for(int j=0;j<bytes.Length;j++)Marshal.WriteByte(input.Data,j,0);Marshal.FreeHGlobal(input.Data);Array.Clear(bytes,0,bytes.Length);}
                }
                return results;
            }finally{if(initialized&&shutdown!=null)shutdown();FreeLibrary(library);}
        }
    }
}
