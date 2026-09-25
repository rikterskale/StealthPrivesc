using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;

namespace StealthPrivesc {
    public sealed class HttpResult {
        public int Status;
        public string Reason;
        public string Body;
        public bool Truncated;
        public uint Error;
    }
    public static class NativeNet {
        internal static byte[] Packet(string name, int type, ushort id) {
            var pk = new List<byte>();
            pk.Add((byte)(id >> 8)); pk.Add((byte)(id & 0xFF));
            pk.Add(0x01); pk.Add(0x00);
            pk.Add(0x00); pk.Add(0x01);
            pk.Add(0); pk.Add(0); pk.Add(0); pk.Add(0); pk.Add(0); pk.Add(0);
            foreach (var lbl in name.Split('.')) {
                if (lbl.Length == 0) { continue; }
                byte[] lb = Encoding.ASCII.GetBytes(lbl);
                pk.Add((byte)lb.Length);
                foreach (var b in lb) { pk.Add(b); }
            }
            pk.Add(0x00);
            pk.Add((byte)(type >> 8)); pk.Add((byte)(type & 0xFF));
            pk.Add(0x00); pk.Add(0x01);
            return pk.ToArray();
        }
        public static string Resolve(string name, string server, int timeout, int type) {
            int ms = timeout < 0 ? 2000 : timeout;
            try {
                using (var sock = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp)) {
                    sock.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveTimeout, ms);
                    sock.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.SendTimeout, ms);
                    ushort id = (ushort)((Environment.TickCount & 0xFFFF) ^ (name.Length & 0xFFFF));
                    sock.Connect(new IPEndPoint(IPAddress.Parse(server), 53));
                    sock.Send(Packet(name, type, id));
                    var rb = new byte[4096];
                    int got = sock.Receive(rb);
                    if (got < 12) { return ""; }
                    int qd = (rb[4] << 8) | rb[5];
                    int an = (rb[6] << 8) | rb[7];
                    int o = 12;
                    for (int i = 0; i < qd; i++) {
                        while (o < rb.Length && rb[o] != 0) { o += rb[o] + 1; }
                        if (o >= rb.Length) { return ""; }
                        o += 5;
                    }
                    var rows = new List<string>();
                    for (int i = 0; i < an; i++) {
                        if (o + 10 > rb.Length) { break; }
                        if ((rb[o] & 0xC0) == 0xC0) { o += 2; } else { while (o < rb.Length && rb[o] != 0) { o += rb[o] + 1; o++; } }
                        if (o + 10 > rb.Length) { break; }
                        int rt = (rb[o] << 8) | rb[o + 1];
                        o += 8;
                        int rl = (rb[o] << 8) | rb[o + 1];
                        o += 2;
                        if (o + rl > rb.Length) { break; }
                        if (rt == 1 && rl >= 4) { rows.Add(new IPAddress(new byte[] { rb[o], rb[o + 1], rb[o + 2], rb[o + 3] }).ToString()); }
                        else if (rt == 28 && rl >= 16) { var a = new byte[16]; Array.Copy(rb, o, a, 0, 16); rows.Add(new IPAddress(a).ToString()); }
                        else if (rl > 0) { rows.Add(Encoding.ASCII.GetString(rb, o, rl)); }
                        o += rl;
                    }
                    return string.Join(",", rows);
                }
            } catch { return ""; }
        }
        public static HttpResult Request(string host, int port, string method, string path, IDictionary<string,string> headers, byte[] body, int timeout, int maximum) {
            var res = new HttpResult();
            int ms = timeout < 0 ? 3000 : timeout;
            using (var sock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)) {
                sock.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.SendTimeout, ms);
                sock.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveTimeout, ms);
                try { sock.Connect(new IPEndPoint(IPAddress.Parse(host), port)); }
                catch { res.Error = (uint)Marshal.GetLastWin32Error(); if (res.Error == 0) { res.Error = 10060; } return res; }
                var hdrs = headers ?? (IDictionary<string,string>)new Dictionary<string,string>();
                var rq = new StringBuilder();
                rq.Append(method).Append(' ').Append(string.IsNullOrEmpty(path) ? "/" : path).Append(" HTTP/1.1\r\n");
                if (!HasKey(hdrs, "Host")) { rq.Append("Host: ").Append(host); if (port != 80 && port != 443) { rq.Append(':').Append(port); } rq.Append("\r\n"); }
                foreach (var h in hdrs) { rq.Append(h.Key).Append(": ").Append(h.Value).Append("\r\n"); }
                if (!HasKey(hdrs, "Content-Length")) { rq.Append("Content-Length: ").Append(body == null ? 0 : body.Length).Append("\r\n"); }
                if (!HasKey(hdrs, "Connection")) { rq.Append("Connection: close\r\n"); }
                rq.Append("\r\n");
                try { sock.Send(Encoding.ASCII.GetBytes(rq.ToString())); if (body != null) { sock.Send(body); } }
                catch { res.Error = (uint)Marshal.GetLastWin32Error(); if (res.Error == 0) { res.Error = 10053; } return res; }
                var stream = new MemoryStream();
                var rb = new byte[8192];
                bool head = false;
                int boundary = -1;
                int clen = -1;
                while (true) {
                    int n;
                    try { n = sock.Receive(rb); }
                    catch (SocketException) { if (!head && res.Error == 0) { res.Error = 10060; } break; }
                    if (n <= 0) { break; }
                    stream.Write(rb, 0, n);
                    if (!head) {
                        int p = Boundary(stream.ToArray());
                        if (p >= 0) {
                            boundary = p; head = true;
                            string hd = Encoding.ASCII.GetString(stream.ToArray(), 0, boundary);
                            int nl = hd.IndexOf("\r\n");
                            if (nl >= 0) {
                                string[] parts = hd.Substring(0, nl).Split(' ');
                                if (parts.Length >= 2 && int.TryParse(parts[1], out int code)) { res.Status = code; } else { res.Status = -1; }
                                if (parts.Length > 2) { res.Reason = string.Join(" ", parts, 2, parts.Length - 2); }
                                foreach (var ln in hd.Substring(nl + 2).Split(new string[] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries)) {
                                    int ci = ln.IndexOf(':');
                                    if (ci > 0 && ln.Substring(0, ci).Trim().Equals("Content-Length", StringComparison.OrdinalIgnoreCase) && int.TryParse(ln.Substring(ci + 1).Trim(), out int cl)) { clen = cl; }
                                }
                            }
                        }
                    }
                    if (head) {
                        int have = (int)stream.Length - boundary - 4;
                        if (have < 0) { have = 0; }
                        if ((clen >= 0 && have >= clen) || stream.Length >= maximum + 4) { if (stream.Length >= maximum + 4) { res.Truncated = true; } break; }
                    }
                }
                if (!head) { if (stream.Length == 0 && res.Error == 0) { res.Error = 10060; } return res; }
                int bh = (int)stream.Length - boundary - 4;
                if (bh < 0) { bh = 0; }
                if (bh > maximum) { bh = maximum; }
                var bod = new byte[bh];
                Array.Copy(stream.ToArray(), boundary + 4, bod, 0, bh);
                res.Body = Encoding.UTF8.GetString(bod);
            }
            return res;
        }
        internal static int Boundary(byte[] data) {
            for (int i = 0; i + 3 < data.Length; i++) {
                if (data[i] == '\r' && data[i + 1] == '\n' && data[i + 2] == '\r' && data[i + 3] == '\n') { return i; }
            }
            return -1;
        }
        internal static bool HasKey(IDictionary<string,string> d, string key) {
            foreach (var k in d.Keys) { if (string.Equals(k, key, StringComparison.OrdinalIgnoreCase)) { return true; } }
            return false;
        }
    }
}
