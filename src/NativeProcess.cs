using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading.Tasks;
namespace StealthPrivesc {
    public static class NativeProcess {
        static string ReadBounded(StreamReader reader, int maximum) {
            var output=new StringBuilder();var buffer=new char[4096];int count;
            while((count=reader.Read(buffer,0,buffer.Length))>0) {
                if(output.Length>maximum-count)throw new InvalidDataException("Helper output exceeds its size budget.");
                output.Append(buffer,0,count);
            }
            return output.ToString();
        }
        public static string Run(string file,string arguments,int seconds,int maximum) {
            using(var process=new Process()) {
                process.StartInfo=new ProcessStartInfo(file,arguments) {UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true};
                if(String.Equals(Path.GetFileNameWithoutExtension(file),"powershell",StringComparison.OrdinalIgnoreCase)) {
                    string modules=Path.Combine(Path.GetDirectoryName(Path.GetFullPath(file)),"Modules");
                    process.StartInfo.EnvironmentVariables["PSModulePath"]=modules+Path.PathSeparator+Environment.GetEnvironmentVariable("PSModulePath");
                }
                process.Start();var watch=Stopwatch.StartNew();
                var stdout=Task.Run(()=>ReadBounded(process.StandardOutput,maximum));
                var stderr=Task.Run(()=>ReadBounded(process.StandardError,maximum));
                try {
                    while(true) {
                        if(stdout.IsFaulted || stderr.IsFaulted)throw new InvalidDataException("Helper output exceeds its size budget or could not be read.");
                        if(watch.Elapsed.TotalSeconds>=seconds) {
                            var failure=new TimeoutException("Read-only helper exceeded its time limit.");failure.Data["StealthPrivesc.TimeoutSeconds"]=seconds;throw failure;
                        }
                        if(process.WaitForExit(25)) {
                            if(stdout.IsCompleted && stderr.IsCompleted)break;
                            System.Threading.Thread.Sleep(25);
                        }
                    }
                    if(process.ExitCode!=0) {
                        var failure=new InvalidOperationException("Read-only helper returned a nonzero exit code.");failure.Data["StealthPrivesc.ExitCode"]=process.ExitCode;throw failure;
                    }
                    return stdout.GetAwaiter().GetResult();
                } finally {
                    try {if(!process.HasExited)process.Kill();}catch(InvalidOperationException){}
                    // Closing inherited streams also bounds drain time after an
                    // exited helper whose descendant still holds a pipe open.
                    process.StandardOutput.Dispose();process.StandardError.Dispose();
                    try {Task.WaitAll(new Task[]{stdout,stderr},1000);}catch(AggregateException){}
                }
            }
        }
    }
}
