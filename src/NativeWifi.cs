using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Xml;
namespace StealthPrivesc {
    public sealed class WifiEvidence {public string InterfaceId,ProfileName,Authentication;public bool KeyPresent,PlaintextKeyReturned,Enterprise;public string[] Validation;public uint Status;public string Value="[REDACTED]";}
    public sealed class WifiQuery {public WifiEvidence[] Items;public uint Status;public bool Truncated;}
    public static class NativeWifi {
        [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct Interface {public Guid Id;[MarshalAs(UnmanagedType.ByValTStr,SizeConst=256)] public string Description;public int State;}
        [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct Profile { [MarshalAs(UnmanagedType.ByValTStr,SizeConst=256)]public string Name;public uint Flags;}
        [DllImport("wlanapi.dll")] static extern uint WlanOpenHandle(uint version,IntPtr reserved,out uint negotiated,out IntPtr client);
        [DllImport("wlanapi.dll")] static extern uint WlanCloseHandle(IntPtr client,IntPtr reserved);
        [DllImport("wlanapi.dll")] static extern uint WlanEnumInterfaces(IntPtr client,IntPtr reserved,out IntPtr list);
        [DllImport("wlanapi.dll")] static extern uint WlanGetProfileList(IntPtr client,ref Guid id,IntPtr reserved,out IntPtr list);
        [DllImport("wlanapi.dll",CharSet=CharSet.Unicode)] static extern uint WlanGetProfile(IntPtr client,ref Guid id,string name,IntPtr reserved,out IntPtr xml,ref uint flags,out uint access);
        [DllImport("wlanapi.dll")] static extern void WlanFreeMemory(IntPtr memory);
        public static WifiQuery Inspect(int maximum,bool plaintext){
            IntPtr client,interfaces=IntPtr.Zero;uint negotiated,status=WlanOpenHandle(2,IntPtr.Zero,out negotiated,out client);var items=new List<WifiEvidence>();var result=new WifiQuery();
            if(status!=0)return new WifiQuery{Status=status,Items=items.ToArray()};
            try{
                status=WlanEnumInterfaces(client,IntPtr.Zero,out interfaces);if(status!=0){result.Status=status;return result;}
                int count=Marshal.ReadInt32(interfaces);if(count<0||count>1024)throw new InvalidOperationException("Invalid WLAN interface count.");
                for(int i=0;i<count;i++){
                    var face=(Interface)Marshal.PtrToStructure(IntPtr.Add(interfaces,8+i*Marshal.SizeOf(typeof(Interface))),typeof(Interface));IntPtr profiles=IntPtr.Zero;
                    try{status=WlanGetProfileList(client,ref face.Id,IntPtr.Zero,out profiles);if(status!=0){items.Add(new WifiEvidence{InterfaceId=face.Id.ToString(),Status=status});continue;}
                        int total=Marshal.ReadInt32(profiles);if(total<0||total>100000)throw new InvalidOperationException("Invalid WLAN profile count.");
                        for(int j=0;j<total;j++){
                            if(items.Count>=maximum){result.Truncated=true;return result;}
                            var profile=(Profile)Marshal.PtrToStructure(IntPtr.Add(profiles,8+j*Marshal.SizeOf(typeof(Profile))),typeof(Profile));IntPtr xml=IntPtr.Zero;int chars=0;uint flags=plaintext?4u:0u,access;
                            var item=new WifiEvidence{InterfaceId=face.Id.ToString(),ProfileName=profile.Name};items.Add(item);
                            try{
                                status=WlanGetProfile(client,ref face.Id,profile.Name,IntPtr.Zero,out xml,ref flags,out access);item.Status=status;if(status!=0)continue;
                                string content=Marshal.PtrToStringUni(xml);chars=content.Length;
                                var settings=new XmlReaderSettings{DtdProcessing=DtdProcessing.Prohibit,XmlResolver=null,MaxCharactersInDocument=1048576};var document=new XmlDocument{XmlResolver=null};using(var reader=XmlReader.Create(new StringReader(content),settings))document.Load(reader);
                                var auth=document.SelectSingleNode("//*[local-name()='authentication']");item.Authentication=auth==null?null:auth.InnerText;
                                var key=document.SelectSingleNode("//*[local-name()='sharedKey']/*[local-name()='keyMaterial']");var protect=document.SelectSingleNode("//*[local-name()='sharedKey']/*[local-name()='protected']");item.KeyPresent=key!=null&&!String.IsNullOrEmpty(key.InnerText);item.PlaintextKeyReturned=item.KeyPresent&&protect!=null&&protect.InnerText.Equals("false",StringComparison.OrdinalIgnoreCase);
                                item.Enterprise=document.SelectSingleNode("//*[local-name()='EAPConfig']")!=null;
                                var validation=new List<string>();foreach(XmlNode node in document.SelectNodes("//*[local-name()='PerformServerValidation' or local-name()='DisableUserPromptForServerValidation' or local-name()='ServerNames' or local-name()='TrustedRootCA' or local-name()='AcceptServerName']")){validation.Add(node.LocalName+"="+node.InnerText);}item.Validation=validation.ToArray();
                            }finally{if(xml!=IntPtr.Zero){for(int k=0;k<chars*2;k++)Marshal.WriteByte(xml,k,0);WlanFreeMemory(xml);}}
                        }
                    }finally{if(profiles!=IntPtr.Zero)WlanFreeMemory(profiles);}
                }
                return result;
            }finally{result.Items=items.ToArray();if(interfaces!=IntPtr.Zero)WlanFreeMemory(interfaces);WlanCloseHandle(client,IntPtr.Zero);}
        }
    }
}
