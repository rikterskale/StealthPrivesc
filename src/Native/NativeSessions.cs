using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
namespace StealthPrivesc {
    public sealed class TabNavigation {public int TabId,Index;public string Url;public bool Selected;}
    public static class NativeSessions {
        public static string Firefox(byte[] data,int maximum){
            if(data.Length<12||Encoding.ASCII.GetString(data,0,8)!="mozLz40\0")throw new InvalidDataException("Invalid Mozilla LZ4 header.");
            uint expected=BitConverter.ToUInt32(data,8);if(expected>maximum)throw new InvalidDataException("Session expands beyond size limit.");var output=new byte[expected];int source=12,destination=0;
            while(source<data.Length){
                byte token=data[source++];int literals=token>>4;
                if(literals==15){byte extra;do{if(source>=data.Length)throw new InvalidDataException();extra=data[source++];literals=checked(literals+extra);}while(extra==255);}
                if(literals>data.Length-source||literals>output.Length-destination)throw new InvalidDataException();Array.Copy(data,source,output,destination,literals);source+=literals;destination+=literals;if(source==data.Length)break;
                if(source+2>data.Length)throw new InvalidDataException();int offset=data[source]|data[source+1]<<8;source+=2;if(offset==0||offset>destination)throw new InvalidDataException();int count=(token&15)+4;
                if((token&15)==15){byte extra;do{if(source>=data.Length)throw new InvalidDataException();extra=data[source++];count=checked(count+extra);}while(extra==255);}
                if(count>output.Length-destination)throw new InvalidDataException();for(int i=0;i<count;i++){output[destination]=output[destination-offset];destination++;}
            }
            if(destination!=output.Length)throw new InvalidDataException("Truncated session.");return Encoding.UTF8.GetString(output);
        }
        public static TabNavigation[] Chromium(byte[] data,int maximum){
            if(data.Length<8||Encoding.ASCII.GetString(data,0,4)!="SNSS")throw new InvalidDataException("Invalid Chromium session header.");int version=BitConverter.ToInt32(data,4);if(version!=1&&version!=3)throw new NotSupportedException("Encrypted or unknown session version.");
            var tabs=new Dictionary<int,Dictionary<int,TabNavigation>>();var selected=new Dictionary<int,int>();int position=8,records=0;
            while(position<data.Length){
                if(position+2>data.Length)throw new InvalidDataException();int length=BitConverter.ToUInt16(data,position);position+=2;if(length<1||length>data.Length-position)throw new InvalidDataException();int id=data[position],body=position+1,available=length-1;position+=length;if(++records>maximum*100)throw new InvalidDataException("Session record limit reached.");
                if(id==6&&available>=16){ // Pickle payload size, tab id, navigation index, UTF-8 URL length.
                    int tab=BitConverter.ToInt32(data,body+4),index=BitConverter.ToInt32(data,body+8),bytes=BitConverter.ToInt32(data,body+12);if(bytes<0||bytes>available-16)throw new InvalidDataException();
                    if(!tabs.ContainsKey(tab)){if(tabs.Count>=maximum)throw new InvalidDataException("Session tab limit reached.");tabs[tab]=new Dictionary<int,TabNavigation>();}
                    tabs[tab][index]=new TabNavigation{TabId=tab,Index=index,Url=Encoding.UTF8.GetString(data,body+16,bytes)};
                }else if(id==7&&available>=8){selected[BitConverter.ToInt32(data,body)]=BitConverter.ToInt32(data,body+4);}
                else if(id==16&&available>=4){int tab=BitConverter.ToInt32(data,body);tabs.Remove(tab);selected.Remove(tab);}
            }
            var result=new List<TabNavigation>();foreach(var tab in tabs){int index;if(selected.TryGetValue(tab.Key,out index)&&tab.Value.ContainsKey(index)){var nav=tab.Value[index];nav.Selected=true;result.Add(nav);}else{foreach(var nav in tab.Value.Values){if(result.Count>=maximum)break;result.Add(nav);}}}return result.ToArray();
        }
    }
}
