using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Reflection;
using System.Text;

namespace StealthScanner {
    internal static class Host {
        private static int Fail(string message) {
            Console.Error.WriteLine(message);
            return 2;
        }
        private static string Script(string value) {
            return "'" + (value ?? string.Empty).Replace("'", "''") + "'";
        }
        private static int Bounded(string value, int low, int high, out bool ok) {
            int parsed;
            if (!int.TryParse(value, out parsed) || parsed < low || parsed > high) { ok = false; return 0; }
            ok = true; return parsed;
        }
        private static int Extract(string[] names, string root, out string problem) {
            problem = null;
            try {
                var assembly = typeof(Host).Assembly;
                foreach (string name in names) {
                    string relative = name.Substring(3);
                    string target = Path.GetFullPath(Path.Combine(root, relative));
                    string baseDirectory = Path.GetFullPath(root);
                    if (!target.StartsWith(baseDirectory + Path.DirectorySeparatorChar, StringComparison.Ordinal)) { continue; }
                    Directory.CreateDirectory(Path.GetDirectoryName(target));
                    using (Stream input = assembly.GetManifestResourceStream(name)) {
                        using (Stream sink = File.Create(target)) { input.CopyTo(sink); }
                    }
                }
            } catch (Exception error) {
                problem = "scanner: embedded payload extract failed (" + error.GetType().Name + ").";
            }
            return problem == null ? 0 : 1;
        }
        private static int Main(string[] argv) {
            int[] ids = null;
            string category = null, search = null, driver = null, vuln = null, output = null;
            int maxItems = 0, maxFile = 0, timeout = 0;
            bool list = false, network = false, domain = false, sensitive = false, passthru = false;
            try {
                for (int i = 0; i < argv.Length; i++) {
                    string token = argv[i];
                    string name = token.StartsWith("-", StringComparison.Ordinal) ? token.Substring(1) : token;
                    string value = null;
                    bool flag = false;
                    switch (name) {
                        case "CheckId": case "Category": case "SearchRoot": case "DriverDatabasePath":
                        case "VulnerabilityDatabasePath": case "OutputDirectory": case "MaxItems":
                        case "MaxFileBytes": case "CommandTimeoutSeconds":
                            if (i + 1 >= argv.Length) { return Fail("scanner: missing value for -" + name + Environment.NewLine); }
                            i++; value = argv[i]; break;
                        case "ListChecks": list = true; flag = true; break;
                        case "IncludeNetwork": network = true; flag = true; break;
                        case "IncludeDomain": domain = true; flag = true; break;
                        case "IncludeSensitive": sensitive = true; flag = true; break;
                        case "PassThru": passthru = true; flag = true; break;
                        default: return Fail("scanner: unknown option -" + name + Environment.NewLine);
                    }
                    if (!flag) {
                        bool ok = true;
                        switch (name) {
                            case "CheckId": {
                                var parts = new List<int>();
                                foreach (string part in value.Split(',')) {
                                    if (string.IsNullOrWhiteSpace(part)) { continue; }
                                    int parsed;
                                    if (!int.TryParse(part.Trim(), out parsed)) { ok = false; break; }
                                    parts.Add(parsed);
                                }
                                if (!ok) { return Fail("scanner: bad -CheckId value '" + value + "'" + Environment.NewLine); }
                                ids = parts.ToArray(); break;
                            }
                            case "Category": category = value; break;
                            case "SearchRoot": search = value; break;
                            case "DriverDatabasePath": driver = value; break;
                            case "VulnerabilityDatabasePath": vuln = value; break;
                            case "OutputDirectory": output = value; break;
                            case "MaxItems": maxItems = Bounded(value, 10, 100000, out ok); break;
                            case "MaxFileBytes": maxFile = Bounded(value, 1024, 10485760, out ok); break;
                            case "CommandTimeoutSeconds": timeout = Bounded(value, 1, 300, out ok); break;
                        }
                        if (!ok) { return Fail("scanner: bad value for -" + name + ": " + value + Environment.NewLine); }
                    }
                }
                string root = Path.Combine(Path.GetTempPath(), "stealthnative-" + Environment.ProcessId.ToString("x"));
                string problem = null;
                if (0 != Extract(typeof(Host).Assembly.GetManifestResourceNames().Where(name => name.StartsWith("sp\\", StringComparison.Ordinal)).ToArray(), root, out problem)) { return Fail(problem + Environment.NewLine); }
                string dll = Environment.GetEnvironmentVariable("STEALTHNATIVE");
                if (string.IsNullOrEmpty(dll)) { dll = Path.Combine(root, "stealthnative.dll"); Environment.SetEnvironmentVariable("STEALTHNATIVE", dll); }
                if (!File.Exists(dll)) { return Fail("scanner: native dll not found at " + dll + Environment.NewLine); }
                try {
                    Assembly.LoadFrom(dll);
                } catch (Exception error) { return Fail("scanner: could not load native dll (" + error.GetType().Name + ")." + Environment.NewLine); }
                var script = new StringBuilder();
                script.Append("$ErrorActionPreference='Stop';");
                script.Append("Import-Module ").Append(Script(Path.Combine(root, "StealthPrivesc.psd1"))).Append(" -Force;");
                script.Append("$o=@{};");
                if (ids != null && ids.Length > 0) { script.Append("$o['CheckId']=@(").Append(string.Join(",", ids.Select(item => item.ToString()))).Append(");"); }
                if (!string.IsNullOrEmpty(category)) { script.Append("$o['Category']=").Append(Script(category)).Append(";"); }
                if (list) { script.Append("$o['ListChecks']=$true;"); }
                if (network) { script.Append("$o['IncludeNetwork']=$true;"); }
                if (domain) { script.Append("$o['IncludeDomain']=$true;"); }
                if (sensitive) { script.Append("$o['IncludeSensitive']=$true;"); }
                if (maxItems > 0) { script.Append("$o['MaxItems']=").Append(maxItems).Append(";"); }
                if (maxFile > 0) { script.Append("$o['MaxFileBytes']=").Append(maxFile).Append(";"); }
                if (timeout > 0) { script.Append("$o['CommandTimeoutSeconds']=").Append(timeout).Append(";"); }
                if (!string.IsNullOrEmpty(search)) { script.Append("$o['SearchRoot']=").Append(Script(search)).Append(";"); }
                if (!string.IsNullOrEmpty(driver)) { script.Append("$o['DriverDatabasePath']=").Append(Script(driver)).Append(";"); }
                if (!string.IsNullOrEmpty(vuln)) { script.Append("$o['VulnerabilityDatabasePath']=").Append(Script(vuln)).Append(";"); }
                if (!string.IsNullOrEmpty(output)) { script.Append("$o['OutputDirectory']=").Append(Script(output)).Append(";"); }
                if (passthru) { script.Append("$o['PassThru']=$true;"); }
                script.Append("$r=Invoke-StealthPrivesc @o");
                if (list || passthru) { script.Append("; $r | ConvertTo-Json -Depth 8"); }
                using (var engine = PowerShell.Create()) {
                    engine.AddScript(script.ToString());
                    var results = engine.Invoke();
                    if (engine.HadErrors) {
                        foreach (var record in engine.Streams.Error) { Console.Error.WriteLine(record.ToString()); }
                        return 1;
                    }
                    if (results != null) { foreach (var item in results) { if (item != null) { Console.WriteLine(item.ToString()); } } }
                }
            } catch (Exception error) {
                return Fail("scanner: host error (" + error.GetType().Name + "): " + error.Message + Environment.NewLine);
            }
            return 0;
        }
    }
}
