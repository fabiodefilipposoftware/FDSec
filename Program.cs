using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace FDSecOptimized
{
    // ============================= 
    // NODI LOGICI (AND/OR/Pattern) 
    // ============================= 
    abstract class SigNode
    {
        public abstract bool Eval(byte[] hits);
        public abstract void Collect(HashSet<string> set);
    }

    sealed class PatternNode : SigNode
    {
        public string Id;
        public int Index;

        public PatternNode(string id) => Id = id;

        public override bool Eval(byte[] hits) =>
            (hits[Index >> 6] & (1UL << (Index & 63))) != 0;

        public override void Collect(HashSet<string> set) => set.Add(Id);
    }

    sealed class AndNode : SigNode
    {
        public List<SigNode> Children = new List<SigNode>();
        public override bool Eval(byte[] hits)
        {
            foreach (var c in Children)
                if (!c.Eval(hits)) return false;
            return true;
        }
        public override void Collect(HashSet<string> set)
        {
            foreach (var c in Children) c.Collect(set);
        }
    }

    sealed class OrNode : SigNode
    {
        public List<SigNode> Children = new List<SigNode>();
        public override bool Eval(byte[] hits)
        {
            foreach (var c in Children)
                if (c.Eval(hits)) return true;
            return false;
        }
        public override void Collect(HashSet<string> set)
        {
            foreach (var c in Children) c.Collect(set);
        }
    }

    // ============================= 
    // PARSER FIRMA 
    // ============================= 
    static class SignatureParser
    {
        public static SigNode Parse(string input)
        {
            input = input.Trim();
            return ParseOr(input);
        }

        private static SigNode ParseOr(string s)
        {
            var parts = SplitTopLevel(s, "OR");
            if (parts.Count == 1) return ParseAnd(parts[0]);
            var node = new OrNode();
            foreach (var p in parts) node.Children.Add(ParseAnd(p));
            return node;
        }

        private static SigNode ParseAnd(string s)
        {
            var parts = SplitTopLevel(s, "AND");
            if (parts.Count == 1) return ParseTerm(parts[0]);
            var node = new AndNode();
            foreach (var p in parts) node.Children.Add(ParseTerm(p));
            return node;
        }

        private static SigNode ParseTerm(string s)
        {
            s = s.Trim();
            if (s.StartsWith("(") && s.EndsWith(")")) return Parse(s.Substring(1, s.Length -2));
            return new PatternNode(s);
        }

        private static List<string> SplitTopLevel(string s, string op)
        {
            var parts = new List<string>();
            int depth = 0, last = 0;
            for (int i = 0; i <= s.Length - op.Length; i++)
            {
                if (s[i] == '(') depth++;
                else if (s[i] == ')') depth--;
                if (depth == 0 &&
                    s.Substring(i).StartsWith(op, StringComparison.OrdinalIgnoreCase))
                {
                    parts.Add(s.Substring(last, i - last));
                    last = i + op.Length;
                }
            }
            parts.Add(s.Substring(last));
            return parts;
        }
    }

    // ============================= 
    // AHO-CORASICK (bitset) 
    // ============================= 
    sealed class AhoNode
    {
        public AhoNode[] Next = new AhoNode[256];
        public AhoNode Fail;
        public List<int> Outputs;
    }

    sealed class AhoCorasick
    {
        private readonly AhoNode _root = new AhoNode();
        public AhoNode root => _root;
        public void AddPattern(byte[] pattern, int id)
        {
            var node = _root;
            foreach (var b in pattern)
            {
                if (node.Next[b] == null) node.Next[b] = new AhoNode();
                node = node.Next[b];
            }
            if (node.Outputs == null)
            {
                node.Outputs = new List<int>();
                node.Outputs.Add(id);
            }
        }

        public void Build()
        {
            var q = new Queue<AhoNode>();
            for (int i = 0; i < 256; i++)
                if (_root.Next[i] != null)
                {
                    _root.Next[i].Fail = _root;
                    q.Enqueue(_root.Next[i]);
                }

            while (q.Count > 0)
            {
                var current = q.Dequeue();
                for (int i = 0; i < 256; i++)
                {
                    var child = current.Next[i];
                    if (child == null) continue;

                    var fail = current.Fail;
                    while (fail != null && fail.Next[i] == null) fail = fail.Fail;
                    child.Fail = fail != null ? fail.Next[i] : _root;

                    if (child.Fail.Outputs != null)
                    {
                        if (child.Outputs == null)
                        {
                            child.Outputs = new List<int>();
                            child.Outputs.AddRange(child.Fail.Outputs);
                        }
                    }

                    q.Enqueue(child);
                }
            }
        }

        public void Scan(byte[] data, ulong[] hits, byte[] rareBytes)
        {
            var node = _root;
            for (int i = 0; i < data.Length; i++)
            {
                byte b = data[i];
                // PREFILTER: ignora byte che non fanno parte dei più rari dei pattern 
                if (rareBytes[b] == 0) continue;

                while (node != null && node.Next[b] == null)
                    node = node.Fail;

                if (node == null)
                {
                    node = _root;
                    node = node.Next[b] ?? node;
                }
                if (node.Outputs != null)
                    foreach (var id in node.Outputs)
                        hits[id >> 6] |= 1UL << (id & 63);

            }
        }
    }

    // ============================= 
    // UTILS 
    // ============================= 
    static class Utils
    {
        public static byte[] HexToBytes(string hex)
        {
            hex = hex.Replace(" ", "");
            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return bytes;
        }

        public static byte[] BuildRareByteMap(IEnumerable<string> patterns)
        {
            byte[] counts = new byte[256];
            foreach (var p in patterns)
            {
                byte[] b = HexToBytes(p);
                foreach (var x in b) counts[x]++;
            }
            // rarità = 1 se presente meno volte 
            for (int i = 0; i < 256; i++) counts[i] = (byte)(counts[i] <= 1 ? 1 : 0);
            return counts;
        }
    }


    // ============================= 
    // ENTRY POINT 
    // ============================= 
    internal class Program
    {
        private static async Task<string[]> DatasetSignature()
        {
            try
            {
                using (HttpClient hc = new HttpClient())
                {
                    return (await hc.GetStringAsync("https://raw.githubusercontent.com/fabiodefilipposoftware/FDSec/refs/heads/main/Database/malwaresignatures.txt")).Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);
                }
            }
            catch (Exception ex) { Console.Error.WriteLine(ex.Message + "\r\n" + ex.StackTrace); }
            return null;
        }

        private static async Task<string[]> DatabaseHashes()
        {
            try
            {
                using (HttpClient hc = new HttpClient())
                {
                    return (await hc.GetStringAsync("https://raw.githubusercontent.com/fabiodefilipposoftware/FDSec/refs/heads/main/Database/malwarehashes.txt")).Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);
                }
            }
            catch(Exception ex) { Console.Error.WriteLine(ex.Message + "\r\n" + ex.StackTrace); }
            return null;
        }

        private static async Task<bool> CheckSignature(string[] signatures, string processname)
        {
            foreach (string signature in signatures)
            {
                // Parse 
                SigNode tree = SignatureParser.Parse(signature);

                // Raccolgo pattern unici 
                var unique = new HashSet<string>();
                tree.Collect(unique);

                var map = unique.Select((p, i) => (p, i)).ToDictionary(x => x.p, x => x.i);
                AssignIndexes(tree, map);

                // Build Aho-Corasick 
                var aho = new AhoCorasick();
                foreach (var kv in map)
                    aho.AddPattern(Utils.HexToBytes(kv.Key), kv.Value);
                aho.Build();

                // Costruisco rareBytes prefilter 
                byte[] rareBytes = Utils.BuildRareByteMap(unique);

                using (var mmf = MemoryMappedFile.CreateFromFile(processname, FileMode.Open, null, 0, MemoryMappedFileAccess.Read))
                {
                    using (var view = mmf.CreateViewAccessor(0, 0, MemoryMappedFileAccess.Read))
                    {

                        long length = view.Capacity;
                        const int CHUNK = 4 * 1024 * 1024;
                        byte[] buffer = new byte[CHUNK];
                        int maxPatternLen = unique.Max(p => p.Length / 2);
                        int overlap = maxPatternLen - 1;
                        byte[] hitBits = new byte[(map.Count + 63) >> 6];

                        long offset = 0;
                        int carry = 0;

                        while (offset < length)
                        {
                            int toRead = (int)Math.Min(CHUNK, length - offset);
                            view.ReadArray(offset, buffer, carry, toRead);

                            int total = carry + toRead;
                            AhoNode node = new AhoCorasick().root;
                            for (int i = 0; i < total; i++)
                            {
                                byte b = buffer[i];
                                if (rareBytes[b] == 0) continue;
                                while (node != null && node.Next[b] == null)

                                    carry = Math.Min(overlap, total);
                                Buffer.BlockCopy(buffer, total - carry, buffer, 0, carry);
                                offset += toRead;
                            }

                            if (tree.Eval(hitBits))
                            {
                                return true;
                            }
                        }
                    }
                }
                /*string hexsign = "^" + signature.Replace("(", "(?:(?=.*").Replace(" AND ", ")(?=.*").Replace(" OR ", "|");
                if (Regex.IsMatch(malwarebuffer, hexsign, RegexOptions.Singleline | RegexOptions.Compiled | RegexOptions.Compiled))
                {
                    return true;
                }*/
            }
            return false;
        }

        static async Task Main(string[] args)
        {
            using (SHA256 sha = SHA256.Create())
            {
                Console.Error.WriteLine("loading database hashes...");
                HashSet<string> blackhashes = new HashSet<string>(await DatabaseHashes(), StringComparer.OrdinalIgnoreCase);
                Console.Error.WriteLine("loading dataset signatures...");
                string[] signatures = await DatasetSignature();
                if (blackhashes != null && signatures != null)
                {
                    Console.Error.WriteLine("Start!");
                    Console.Error.WriteLine(blackhashes.Count.ToString() + " hashes and " + signatures.Length + " signatures");
                    if (args.Length == 1)
                    {
                        try
                        {
                            if (File.Exists(args[0]))
                            {
                                string malwarehash = BitConverter.ToString(sha.ComputeHash(File.ReadAllBytes(args[0]))).Replace("-", String.Empty).ToLower();
                                if (blackhashes.Contains(malwarehash) || await CheckSignature(signatures, args[0]))
                                {
                                    Console.Error.WriteLine("MALWARE FOUND! " + args[0]);
                                    Process.Start(new ProcessStartInfo
                                    {
                                        FileName = "cmd.exe",
                                        Arguments = $"/c tar -acf quarantine.zip {args[0]} && del {args[0]}",
                                        CreateNoWindow = true,
                                        UseShellExecute = false
                                    }).WaitForExit();
                                }
                            }
                        }
                        catch { }
                    }
                    else
                    {

                        while (true)
                        {
                            // Scan processi 
                            foreach (Process proc in Process.GetProcesses())
                            {
                                if (proc.Id != Process.GetCurrentProcess().Id)
                                {
                                    try
                                    {
                                        byte[] malwarebuffer = File.ReadAllBytes(proc.MainModule.FileName);
                                        if (malwarebuffer != null)
                                        {
                                            string malwarehash = BitConverter.ToString(sha.ComputeHash(malwarebuffer)).Replace("-", String.Empty).ToLower();
                                            if (blackhashes.Contains(malwarehash) || await CheckSignature(signatures, proc.MainModule.FileName))
                                            {
                                                Process.Start(new ProcessStartInfo
                                                {
                                                    FileName = "taskkill",
                                                    Arguments = $"/F /T /PID {proc.Id} && tar -acf quarantine.zip {proc.MainModule.FileName} && del {proc.MainModule.FileName}",
                                                    CreateNoWindow = true,
                                                    UseShellExecute = false
                                                }).WaitForExit();
                                            }
                                        }
                                    }
                                    catch { }
                                }
                            }
                            Thread.Sleep(250);
                        }
                    }
                }
            }
        }

        static void AssignIndexes(SigNode node, Dictionary<string, int> map)
        {
            switch (node)
            {
                case PatternNode p: p.Index = map[p.Id]; break;
                case AndNode a: foreach (var c in a.Children) AssignIndexes(c, map); break;
                case OrNode o: foreach (var c in o.Children) AssignIndexes(c, map); break;
            }
        }
    }
}