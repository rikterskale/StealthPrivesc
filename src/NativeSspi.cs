using System;
using System.Runtime.InteropServices;

namespace StealthPrivesc {
    public sealed class SspiExposure {
        public string Package="NTLM",Stage,State; public uint Status; public int AuthenticationTokenBytes,ResponseBytes;
        public bool CredentialResponseReturned; public string Value="[REDACTED]";
    }
    public static class NativeSspi {
        [StructLayout(LayoutKind.Sequential)] struct Handle { public IntPtr Lower,Upper; public bool IsSet { get{return Lower!=IntPtr.Zero || Upper!=IntPtr.Zero;} } }
        [StructLayout(LayoutKind.Sequential)] struct Buffer { public int Length,Type; public IntPtr Data; }
        [StructLayout(LayoutKind.Sequential)] struct Descriptor { public int Version,Count; public IntPtr Buffers; }
        sealed class TokenBuffer : IDisposable {
            public Descriptor Descriptor;
            public TokenBuffer(){Descriptor=new Descriptor{Count=1,Buffers=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Buffer)))};Marshal.StructureToPtr(new Buffer{Type=2},Descriptor.Buffers,false);}
            public Buffer Value {get{return (Buffer)Marshal.PtrToStructure(Descriptor.Buffers,typeof(Buffer));}}
            public void Dispose(){var value=Value;if(value.Data!=IntPtr.Zero){for(int i=0;i<value.Length;i++)Marshal.WriteByte(value.Data,i,0);FreeContextBuffer(value.Data);}Marshal.FreeHGlobal(Descriptor.Buffers);}
        }
        [DllImport("secur32.dll",CharSet=CharSet.Unicode)] static extern uint AcquireCredentialsHandle(string principal,string package,uint use,IntPtr logon,IntPtr auth,IntPtr callback,IntPtr argument,out Handle credentials,out long expiry);
        [DllImport("secur32.dll",CharSet=CharSet.Unicode,EntryPoint="InitializeSecurityContextW")] static extern uint InitializeFirst(ref Handle credentials,IntPtr context,string target,uint request,uint reserved,uint dataRep,IntPtr input,uint reserved2,out Handle updated,ref Descriptor output,out uint attributes,out long expiry);
        [DllImport("secur32.dll",CharSet=CharSet.Unicode,EntryPoint="InitializeSecurityContextW")] static extern uint InitializeNext(ref Handle credentials,ref Handle context,string target,uint request,uint reserved,uint dataRep,ref Descriptor input,uint reserved2,out Handle updated,ref Descriptor output,out uint attributes,out long expiry);
        [DllImport("secur32.dll")] static extern uint AcceptSecurityContext(ref Handle credentials,IntPtr context,ref Descriptor input,uint request,uint dataRep,out Handle updated,ref Descriptor output,out uint attributes,out long expiry);
        [DllImport("secur32.dll")] static extern uint DeleteSecurityContext(ref Handle handle);
        [DllImport("secur32.dll")] static extern uint FreeCredentialsHandle(ref Handle handle);
        [DllImport("secur32.dll")] static extern uint FreeContextBuffer(IntPtr buffer);
        public static SspiExposure Probe() {
            var result=new SspiExposure{Stage="Acquire",State="Unknown"};Handle credentials=new Handle(),client=new Handle(),server=new Handle();long expiry;
            try{
                result.Status=AcquireCredentialsHandle(null,"NTLM",3,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,out credentials,out expiry);
                if((result.Status&0x80000000)!=0){result.State="Unavailable";return result;}
                using(var negotiate=new TokenBuffer())using(var challenge=new TokenBuffer())using(var authenticate=new TokenBuffer()){
                    uint attributes;
                    result.Stage="Negotiate";
                    result.Status=InitializeFirst(ref credentials,IntPtr.Zero,null,0x900,0,0x10,IntPtr.Zero,0,out client,ref negotiate.Descriptor,out attributes,out expiry);
                    if((result.Status&0x80000000)!=0){result.State="PolicyOrCredentialFailure";return result;}
                    result.Stage="LocalChallenge";
                    result.Status=AcceptSecurityContext(ref credentials,IntPtr.Zero,ref negotiate.Descriptor,0x900,0x10,out server,ref challenge.Descriptor,out attributes,out expiry);
                    if((result.Status&0x80000000)!=0){result.State="PolicyOrCredentialFailure";return result;}
                    // Preserve every server flag and its random challenge. No downgrade, reflection or network exchange.
                    result.Stage="Authenticate";Handle updated;
                    result.Status=InitializeNext(ref credentials,ref client,null,0x900,0,0x10,ref challenge.Descriptor,0,out updated,ref authenticate.Descriptor,out attributes,out expiry);
                    if(updated.IsSet)client=updated;
                    if((result.Status&0x80000000)!=0){result.State="PolicyOrCredentialFailure";return result;}
                    var token=authenticate.Value;result.AuthenticationTokenBytes=token.Length;
                    if(token.Data!=IntPtr.Zero && token.Length>=64 && Marshal.ReadInt32(token.Data,8)==3){
                        int length=unchecked((ushort)Marshal.ReadInt16(token.Data,20));uint offset=unchecked((uint)Marshal.ReadInt32(token.Data,24));
                        if(offset<=token.Length && length<=token.Length-offset){result.ResponseBytes=length;result.CredentialResponseReturned=length>0;}
                    }
                    result.State=result.CredentialResponseReturned?"CredentialResponseReturned":"LocalAuthenticationWithoutResponse";
                    return result;
                }
            }finally{if(client.IsSet)DeleteSecurityContext(ref client);if(server.IsSet)DeleteSecurityContext(ref server);if(credentials.IsSet)FreeCredentialsHandle(ref credentials);}
        }
    }
}
