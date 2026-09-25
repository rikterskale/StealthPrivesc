using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text.RegularExpressions;
using System.Xml;

namespace StealthPrivesc {
    public sealed class TaskInfo {
        public string Path, Account, LogonType, RunLevel, State;
        public readonly List<string> Executables = new List<string>();
        public readonly List<string> Arguments = new List<string>();
        public readonly List<string> WorkDirs = new List<string>();
    }
    public static class NativeTasks {
        internal static string Root {
            get {
                string window = Environment.GetEnvironmentVariable("windir");
                return Path.Combine(string.IsNullOrEmpty(window) ? @"C:\Windows" : window, "System32", "Tasks");
            }
        }
        public static List<TaskInfo> Enumerate(string pattern, int maximum, int depth) {
            var rows = new List<TaskInfo>();
            int cap = maximum < 0 ? 0x7FFFFFFF : maximum;
            int bound = depth < 0 ? 24 : depth;
            string top = Root;
            if (!Directory.Exists(top)) { return rows; }
            Regex rx = string.IsNullOrEmpty(pattern) ? null : new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            var stack = new Queue<Tuple<string, int>>();
            stack.Enqueue(Tuple.Create(top, 0));
            while (stack.Count > 0 && rows.Count < cap) {
                var node = stack.Dequeue();
                if (node.Item2 > bound) { continue; }
                string folder = node.Item1;
                if (!folder.EndsWith("\\")) { folder += "\\"; }
                string[] files;
                try { files = Directory.GetFiles(folder); } catch { files = new string[0]; }
                foreach (string file in files) {
                    if (rows.Count >= cap) { break; }
                    string name = Path.GetFileName(file);
                    if (!name.EndsWith(".xml", StringComparison.OrdinalIgnoreCase)) { continue; }
                    if (rx != null && !rx.IsMatch(name)) { continue; }
                    FileInfo probe = new FileInfo(file);
                    if (probe.Length < 0x10 || probe.Length > 0x40000) { continue; }
                    string rel = file.Substring(top.Length);
                    try { rows.Add(Parse(file, rel)); } catch { }
                }
                if (node.Item2 + 1 <= bound) {
                    string[] subs;
                    try { subs = Directory.GetDirectories(folder); } catch { subs = new string[0]; }
                    foreach (string sub in subs) { stack.Enqueue(Tuple.Create(sub, node.Item2 + 1)); }
                }
            }
            return rows;
        }
        internal static TaskInfo Parse(string file, string rel) {
            var info = new TaskInfo { Path = rel };
            XmlReaderSettings opts = new XmlReaderSettings {
                IgnoreComments = true,
                IgnoreWhitespace = true,
            };
            using (XmlReader reader = XmlReader.Create(file, opts)) {
                while (true) {
                    if (!reader.Read()) { break; }
                    if (reader.NodeType != XmlNodeType.Element) { continue; }
                    string tag = reader.LocalName;
                    string text = reader.ReadString();
                    if (tag == "UserId") { info.Account = text; }
                    else if (tag == "LogonType") { info.LogonType = text; }
                    else if (tag == "RunLevel") { info.RunLevel = text; }
                    else if (tag == "Execute") { if (!string.IsNullOrEmpty(text)) { info.Executables.Add(text); } }
                    else if (tag == "Arguments") { if (!string.IsNullOrEmpty(text)) { info.Arguments.Add(text); } }
                    else if (tag == "WorkingDirectory") { if (!string.IsNullOrEmpty(text)) { info.WorkDirs.Add(text); } }
                    else if (tag == "Enabled") { info.State = text.Trim().Equals("true", StringComparison.OrdinalIgnoreCase) ? "Ready" : "Disabled"; }
                }
            }
            if (string.IsNullOrEmpty(info.State)) { info.State = "Ready"; }
            return info;
        }
    }
}
