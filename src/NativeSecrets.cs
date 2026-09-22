using System;
using System.Runtime.InteropServices;
using System.Text;
namespace StealthPrivesc {
    public sealed class SecretProbe {public bool Recovered;public string Method;public string Value="[REDACTED]";public int Status;}
    public static class NativeSecrets {
        [StructLayout(LayoutKind.Sequential)] struct Blob {public int Size;public IntPtr Data;}
        [StructLayout(LayoutKind.Sequential)] struct AuthInfo {
            public uint Size,Version;public IntPtr Nonce;public uint NonceSize;public IntPtr AuthData;public uint AuthDataSize;public IntPtr Tag;public uint TagSize;public IntPtr Mac;public uint MacSize,AuthSize;public ulong DataSize;public uint Flags;
        }
        [DllImport("crypt32.dll",SetLastError=true)] static extern bool CryptUnprotectData(ref Blob input,IntPtr description,IntPtr entropy,IntPtr reserved,IntPtr prompt,uint flags,out Blob output);
        [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr pointer);
        [DllImport("bcrypt.dll",CharSet=CharSet.Unicode)] static extern int BCryptOpenAlgorithmProvider(out IntPtr handle,string algorithm,string implementation,uint flags);
        [DllImport("bcrypt.dll",CharSet=CharSet.Unicode)] static extern int BCryptSetProperty(IntPtr handle,string property,byte[] value,int length,uint flags);
        [DllImport("bcrypt.dll",CharSet=CharSet.Unicode)] static extern int BCryptGetProperty(IntPtr handle,string property,byte[] value,int length,out int result,uint flags);
        [DllImport("bcrypt.dll")] static extern int BCryptGenerateSymmetricKey(IntPtr algorithm,out IntPtr key,byte[] keyObject,int objectLength,byte[] secret,int secretLength,uint flags);
        [DllImport("bcrypt.dll")] static extern int BCryptDecrypt(IntPtr key,byte[] input,int inputLength,ref AuthInfo auth,IntPtr iv,int ivLength,byte[] output,int outputLength,out int result,uint flags);
        [DllImport("bcrypt.dll")] static extern int BCryptDestroyKey(IntPtr key);
        [DllImport("bcrypt.dll")] static extern int BCryptCloseAlgorithmProvider(IntPtr algorithm,uint flags);
        static void Erase(IntPtr pointer,int length){for(int i=0;i<length;i++)Marshal.WriteByte(pointer,i,0);}
        static byte[] Unprotect(byte[] bytes,out int status){
            var input=new Blob{Size=bytes.Length,Data=Marshal.AllocHGlobal(bytes.Length)};var output=new Blob();
            try{Marshal.Copy(bytes,0,input.Data,bytes.Length);if(!CryptUnprotectData(ref input,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,1,out output)){status=Marshal.GetLastWin32Error();return null;}status=0;var result=new byte[output.Size];Marshal.Copy(output.Data,result,0,result.Length);return result;}
            finally{Erase(input.Data,input.Size);Marshal.FreeHGlobal(input.Data);if(output.Data!=IntPtr.Zero){Erase(output.Data,output.Size);LocalFree(output.Data);}}
        }
        public static SecretProbe Browser(byte[] protectedKey,byte[] encrypted){
            var result=new SecretProbe();byte[] keyBytes=null,plain=null,keyObject=null;GCHandle keyPin=new GCHandle();IntPtr algorithm=IntPtr.Zero,key=IntPtr.Zero,nonce=IntPtr.Zero,tag=IntPtr.Zero;
            try{
                if(encrypted==null||encrypted.Length==0){result.Method="Empty";return result;}
                string prefix=encrypted.Length>=3?Encoding.ASCII.GetString(encrypted,0,3):"";
                if(prefix=="v20"){result.Method="AppBoundUnsupported";return result;}
                if(prefix!="v10"&&prefix!="v11"){result.Method="CurrentUserDPAPI";plain=Unprotect(encrypted,out result.Status);result.Recovered=plain!=null&&plain.Length>0;return result;}
                result.Method="CurrentUserDPAPI_AES_GCM";
                if(protectedKey==null||protectedKey.Length<6||Encoding.ASCII.GetString(protectedKey,0,5)!="DPAPI"||encrypted.Length<31){result.Status=87;return result;}
                var wrapped=new byte[protectedKey.Length-5];Array.Copy(protectedKey,5,wrapped,0,wrapped.Length);try{keyBytes=Unprotect(wrapped,out result.Status);}finally{Array.Clear(wrapped,0,wrapped.Length);}if(keyBytes==null)return result;
                result.Status=BCryptOpenAlgorithmProvider(out algorithm,"AES",null,0);if(result.Status!=0)return result;
                var mode=Encoding.Unicode.GetBytes("ChainingModeGCM\0");result.Status=BCryptSetProperty(algorithm,"ChainingMode",mode,mode.Length,0);if(result.Status!=0)return result;
                var length=new byte[4];int returned;result.Status=BCryptGetProperty(algorithm,"ObjectLength",length,4,out returned,0);if(result.Status!=0)return result;int size=BitConverter.ToInt32(length,0);if(size<0||size>1048576){result.Status=87;return result;}keyObject=new byte[size];
                keyPin=GCHandle.Alloc(keyObject,GCHandleType.Pinned);result.Status=BCryptGenerateSymmetricKey(algorithm,out key,keyObject,keyObject.Length,keyBytes,keyBytes.Length,0);if(result.Status!=0)return result;
                nonce=Marshal.AllocHGlobal(12);Marshal.Copy(encrypted,3,nonce,12);tag=Marshal.AllocHGlobal(16);Marshal.Copy(encrypted,encrypted.Length-16,tag,16);
                var auth=new AuthInfo{Size=(uint)Marshal.SizeOf(typeof(AuthInfo)),Version=1,Nonce=nonce,NonceSize=12,Tag=tag,TagSize=16};var cipher=new byte[encrypted.Length-31];Array.Copy(encrypted,15,cipher,0,cipher.Length);plain=new byte[cipher.Length];
                try{result.Status=BCryptDecrypt(key,cipher,cipher.Length,ref auth,IntPtr.Zero,0,plain,plain.Length,out returned,0);result.Recovered=result.Status==0&&returned>0;}finally{Array.Clear(cipher,0,cipher.Length);}return result;
            }finally{if(key!=IntPtr.Zero)BCryptDestroyKey(key);if(algorithm!=IntPtr.Zero)BCryptCloseAlgorithmProvider(algorithm,0);if(nonce!=IntPtr.Zero){Erase(nonce,12);Marshal.FreeHGlobal(nonce);}if(tag!=IntPtr.Zero){Erase(tag,16);Marshal.FreeHGlobal(tag);}foreach(var bytes in new[]{keyBytes,plain,keyObject})if(bytes!=null)Array.Clear(bytes,0,bytes.Length);if(keyPin.IsAllocated)keyPin.Free();}
        }
    }
}
