using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading.Tasks;
namespace StealthPrivesc {
    public static class Console {
        const long Maximum = 8L*1024*1024; // Hard ceiling for any helper stdout/stderr capture.
        static string Bounded(StreamReader reader, int maximum) {
            var text = new StringBuilder(); var buffer = new char[4096]; int count;
            while ((count = reader.Read(buffer, 0, buffer.Length)) > 0) {
                if (text.Length > maximum - count) throw new InvalidDataException("Helper output exceeds its size budget.");
                text.Append(buffer, 0, count);
            }
            return text.ToString();
        }
        // A hidden, neutral native helper: no PowerShell on the command line, output and run time both bounded.
        public static string Run(string file, string arguments, int seconds, int maximum) {
            using (var process = new Process()) {
                process.StartInfo = new ProcessStartInfo(file, arguments) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
                process.Start();
                var watch = Stopwatch.StartNew();
                var stdout = Task.Run(() => Bounded(process.StandardOutput, maximum));
                var stderr = Task.Run(() => Bounded(process.StandardError, maximum));
                try {
                    while (true) {
                        if (stdout.IsFaulted || stderr.IsFaulted) throw new InvalidDataException("Helper output exceeds its size budget or could not be read.");
                        if (watch.Elapsed.TotalSeconds >= seconds) { var failure = new TimeoutException("Read-only helper exceeded its time limit."); failure.Data["StealthPrivesc.TimeoutSeconds"] = seconds; throw failure; }
                        if (process.WaitForExit(25)) { if (stdout.IsCompleted && stderr.IsCompleted) break; System.Threading.Thread.Sleep(25); }
                    }
                    if (process.ExitCode != 0) { var failure = new InvalidOperationException("Read-only helper returned a nonzero exit code."); failure.Data["StealthPrivesc.ExitCode"] = process.ExitCode; throw failure; }
                    return stdout.GetAwaiter().GetResult();
                } finally {
                    try { if (!process.HasExited) process.Kill(); } catch (InvalidOperationException) { }
                    process.StandardOutput.Dispose(); process.StandardError.Dispose();
                    try { Task.WaitAll(new Task[] { stdout, stderr }, 1000); } catch (AggregateException) { }
                }
            }
        }
        // A hidden PowerShell that reads its script from standard input (-Command -), so the payload never
        // appears on the command line as a base64 beacon.
        public static string Ps(string host, string code, int seconds, int maximum) {
            using (var process = new Process()) {
                var input = new UTF8Encoding(false).GetBytes(code); // UTF-8 without BOM; -Command - expects no leading marker.
                process.StartInfo = new ProcessStartInfo(host, "-STA -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command -") {
                    UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true, RedirectStandardInput = true
                };
                process.Start();
                try { process.StandardInput.BaseStream.Write(input, 0, input.Length); process.StandardInput.Close(); }
                catch (InvalidOperationException) { /* The input pipe closed if the helper failed before reading. */ }
                var watch = Stopwatch.StartNew();
                var stdout = Task.Run(() => Bounded(process.StandardOutput, maximum));
                var stderr = Task.Run(() => Bounded(process.StandardError, maximum));
                try {
                    while (true) {
                        if (stdout.IsFaulted || stderr.IsFaulted) throw new InvalidDataException("Helper output exceeds its size budget or could not be read.");
                        if (watch.Elapsed.TotalSeconds >= seconds) { var failure = new TimeoutException("Read-only helper exceeded its time limit."); failure.Data["StealthPrivesc.TimeoutSeconds"] = seconds; throw failure; }
                        if (process.WaitForExit(25)) { if (stdout.IsCompleted && stderr.IsCompleted) break; System.Threading.Thread.Sleep(25); }
                    }
                    if (process.ExitCode != 0) { var failure = new InvalidOperationException("Read-only helper returned a nonzero exit code."); failure.Data["StealthPrivesc.ExitCode"] = process.ExitCode; throw failure; }
                    return stdout.GetAwaiter().GetResult();
                } finally {
                    try { if (!process.HasExited) process.Kill(); } catch (InvalidOperationException) { }
                    process.StandardOutput.Dispose(); process.StandardError.Dispose();
                    try { Task.WaitAll(new Task[] { stdout, stderr }, 1000); } catch (AggregateException) { }
                }
            }
        }
    }
}
