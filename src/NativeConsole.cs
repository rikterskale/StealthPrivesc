using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading.Tasks;
namespace StealthPrivesc {
    public static class Console {
        const long Maximum = 8L*1024*1024; // Hard ceiling for any helper stdout/stderr capture.
        static long startedProcesses;
        public static long StartedProcesses { get { return System.Threading.Interlocked.Read(ref startedProcesses); } }
        static void Validate(int seconds, int maximum) {
            if (seconds < 1 || seconds > 3600 || maximum < 1024 || maximum > Maximum) throw new ArgumentOutOfRangeException("Invalid helper budget.");
        }
        static InvalidDataException OutputFailure() {
            var failure = new InvalidDataException("Helper output exceeds its size budget or could not be read.");
            failure.Data["StealthPrivesc.BudgetExceeded"] = true;
            failure.Data["StealthPrivesc.BudgetKind"] = "HelperOutput"; return failure;
        }
        static TimeoutException TimeoutFailure(int seconds) {
            var failure = new TimeoutException("Read-only helper exceeded its time limit.");
            failure.Data["StealthPrivesc.TimeoutSeconds"] = seconds;
            failure.Data["StealthPrivesc.BudgetExceeded"] = true;
            failure.Data["StealthPrivesc.BudgetKind"] = "HelperTime"; return failure;
        }
        static void ConfigureModules(ProcessStartInfo start) {
            if (String.Equals(Path.GetFileNameWithoutExtension(start.FileName), "powershell", StringComparison.OrdinalIgnoreCase)) {
                string modules = Path.Combine(Path.GetDirectoryName(Path.GetFullPath(start.FileName)), "Modules");
                start.EnvironmentVariables["PSModulePath"] = modules + Path.PathSeparator + Environment.GetEnvironmentVariable("PSModulePath");
            }
        }
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
            Validate(seconds, maximum);
            using (var process = new Process()) {
                process.StartInfo = new ProcessStartInfo(file, arguments) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
                ConfigureModules(process.StartInfo);
                var watch = Stopwatch.StartNew();
                process.Start();
                System.Threading.Interlocked.Increment(ref startedProcesses);
                var stdout = Task.Run(() => Bounded(process.StandardOutput, maximum));
                var stderr = Task.Run(() => Bounded(process.StandardError, maximum));
                try {
                    while (true) {
                        if (stdout.IsFaulted || stderr.IsFaulted) throw OutputFailure();
                        if (watch.Elapsed.TotalSeconds >= seconds) throw TimeoutFailure(seconds);
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
        // Read the complete UTF-8 script before parsing, so multiline statements
        // execute consistently across Windows PowerShell and PowerShell 7.
        public static string Ps(string host, string code, int seconds, int maximum) {
            Validate(seconds, maximum);
            using (var process = new Process()) {
                var input = new UTF8Encoding(false).GetBytes(code);
                process.StartInfo = new ProcessStartInfo(host, "-STA -NoLogo -NoProfile -NonInteractive -Command \"[Console]::InputEncoding = [Text.Encoding]::UTF8; [Console]::OutputEncoding = [Text.Encoding]::UTF8; & ([scriptblock]::Create([Console]::In.ReadToEnd()))\"") {
                    UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true, RedirectStandardInput = true,
                    StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8
                };
                ConfigureModules(process.StartInfo);
                var watch = Stopwatch.StartNew();
                process.Start();
                System.Threading.Interlocked.Increment(ref startedProcesses);
                // Input writing is part of the same deadline: a helper that does
                // not drain stdin must not block the calling process indefinitely.
                var stdin = Task.Run(() => {
                    try { process.StandardInput.BaseStream.Write(input, 0, input.Length); process.StandardInput.Close(); }
                    catch (InvalidOperationException) { }
                    catch (IOException) { }
                    finally { Array.Clear(input, 0, input.Length); }
                });
                var stdout = Task.Run(() => Bounded(process.StandardOutput, maximum));
                var stderr = Task.Run(() => Bounded(process.StandardError, maximum));
                try {
                    while (true) {
                        if (stdout.IsFaulted || stderr.IsFaulted) throw OutputFailure();
                        if (watch.Elapsed.TotalSeconds >= seconds) throw TimeoutFailure(seconds);
                        if (process.WaitForExit(25)) { if (stdout.IsCompleted && stderr.IsCompleted) break; System.Threading.Thread.Sleep(25); }
                    }
                    if (process.ExitCode != 0) { var failure = new InvalidOperationException("Read-only helper returned a nonzero exit code."); failure.Data["StealthPrivesc.ExitCode"] = process.ExitCode; throw failure; }
                    return stdout.GetAwaiter().GetResult();
                } finally {
                    try { if (!process.HasExited) process.Kill(); } catch (InvalidOperationException) { }
                    try { process.StandardInput.Dispose(); } catch (IOException) { }
                    process.StandardOutput.Dispose(); process.StandardError.Dispose();
                    try { Task.WaitAll(new Task[] { stdin, stdout, stderr }, 1000); } catch (AggregateException) { }
                }
            }
        }
    }
}
