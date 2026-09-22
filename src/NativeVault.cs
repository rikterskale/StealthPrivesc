using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace StealthPrivesc {
    public sealed class VaultExposure {
        public Guid VaultId, SchemaId; public int ItemIndex, RetrievalStatus, AuthenticatorType;
        public bool ResourcePresent, IdentityPresent, SecretReturned; public string Value="[REDACTED]";
    }
    public sealed class VaultResult { public VaultExposure[] Items; public int[] Errors; public bool Truncated; }
    public static class NativeVault {
        [StructLayout(LayoutKind.Sequential)] struct VaultItem {
            public Guid Schema; public IntPtr FriendlyName, Resource, Identity, Authenticator, PackageSid;
            public long Modified; public uint Flags, PropertyCount; public IntPtr Properties;
        }
        [DllImport("vaultcli.dll")] static extern int VaultEnumerateVaults(int flags,out int count,out IntPtr ids);
        [DllImport("vaultcli.dll")] static extern int VaultOpenVault(ref Guid id,uint flags,out IntPtr handle);
        [DllImport("vaultcli.dll")] static extern int VaultCloseVault(ref IntPtr handle);
        [DllImport("vaultcli.dll")] static extern int VaultEnumerateItems(IntPtr vault,int flags,out int count,out IntPtr items);
        [DllImport("vaultcli.dll")] static extern int VaultGetItem(IntPtr vault,ref Guid schema,IntPtr resource,IntPtr identity,IntPtr package,IntPtr window,uint flags,out IntPtr item);
        [DllImport("vaultcli.dll")] static extern void VaultFree(IntPtr memory);
        static bool SecretPresentAndErase(IntPtr element) {
            if(element==IntPtr.Zero)return false;
            int type=Marshal.ReadInt32(element,8);
            if(type==7) {
                IntPtr text=Marshal.ReadIntPtr(element,16);if(text==IntPtr.Zero)return false;
                bool present=Marshal.ReadInt16(text)!=0;
                for(int i=0;i<65536 && Marshal.ReadInt16(text,i*2)!=0;i++)Marshal.WriteInt16(text,i*2,0);
                return present;
            }
            // Byte/protected arrays contain a DWORD length followed by an aligned pointer.
            if(type==8 || type==10) {
                int length=Marshal.ReadInt32(element,16);
                IntPtr bytes=Marshal.ReadIntPtr(element,16+(IntPtr.Size==8?8:4));
                if(length<0 || length>1048576)return false;
                if(bytes!=IntPtr.Zero)for(int i=0;i<length;i++)Marshal.WriteByte(bytes,i,0);
                return bytes!=IntPtr.Zero && length>0;
            }
            return false;
        }
        public static VaultResult Inspect(int maximum) {
            // This ABI is for Windows 8 / Server 2012 and newer, the supported scanner platforms.
            var result=new List<VaultExposure>();var errors=new List<int>();bool truncated=false;
            int count;IntPtr vaults;int status=VaultEnumerateVaults(0,out count,out vaults);
            if(status!=0)return new VaultResult{Items=result.ToArray(),Errors=new int[]{status}};
            try{
                for(int i=0;i<count;i++){
                    Guid id=(Guid)Marshal.PtrToStructure(IntPtr.Add(vaults,16*i),typeof(Guid));IntPtr vault;
                    status=VaultOpenVault(ref id,0,out vault);if(status!=0){errors.Add(status);continue;}
                    try{
                        int itemCount;IntPtr items;status=VaultEnumerateItems(vault,0x200,out itemCount,out items);
                        if(status!=0){if(status!=1168)errors.Add(status);continue;}
                        try{
                            int stride=Marshal.SizeOf(typeof(VaultItem));
                            for(int j=0;j<itemCount;j++){
                                if(result.Count>=maximum){truncated=true;break;}
                                var item=(VaultItem)Marshal.PtrToStructure(IntPtr.Add(items,j*stride),typeof(VaultItem));
                                var exposure=new VaultExposure{VaultId=id,SchemaId=item.Schema,ItemIndex=j,ResourcePresent=item.Resource!=IntPtr.Zero,IdentityPresent=item.Identity!=IntPtr.Zero,AuthenticatorType=-1};
                                IntPtr resolved;
                                exposure.RetrievalStatus=VaultGetItem(vault,ref item.Schema,item.Resource,item.Identity,item.PackageSid,IntPtr.Zero,0,out resolved);
                                if(exposure.RetrievalStatus==0 && resolved!=IntPtr.Zero){
                                    try{
                                        var full=(VaultItem)Marshal.PtrToStructure(resolved,typeof(VaultItem));
                                        if(full.Authenticator!=IntPtr.Zero)exposure.AuthenticatorType=Marshal.ReadInt32(full.Authenticator,8);
                                        exposure.SecretReturned=SecretPresentAndErase(full.Authenticator);
                                    }finally{VaultFree(resolved);}
                                }
                                result.Add(exposure);
                            }
                        }finally{VaultFree(items);}
                    }finally{VaultCloseVault(ref vault);}
                    if(truncated)break;
                }
            }finally{VaultFree(vaults);}
            return new VaultResult{Items=result.ToArray(),Errors=errors.ToArray(),Truncated=truncated};
        }
    }
}
