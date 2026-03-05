using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace FDSec
{
    internal class Program
    {
        [StructLayout(LayoutKind.Sequential)]
        internal struct MibTcpRowOwnerPid
        {
            internal uint state;
            internal uint locaAddr;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)] internal byte[] localPort;
            internal uint remoteAddr;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)] internal byte[] remotePort;
            internal int owningPid;
        }

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int dwOutBufLen, bool sort, int ipVersion, int tblClass, uint reserved = 0);

        private static HashSet<string> blackhashes;
        private static HashSet<string> whitehashes;
        private static HashSet<string> blackIps;
        private static string[] signatures;
        private static SHA256 sha = SHA256.Create();
        private static ulong numfiles = 0;

        private static async Task<string[]> DatasetSignature()
        {
            try
            {
                using (HttpClient hc = new HttpClient())
                {
                    return (await hc.GetStringAsync("https://raw.githubusercontent.com/fabiodefilipposoftware/FDSec/refs/heads/main/Database/malwaresignatures.txt")).Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);
                }
            }
            catch { }
            return null;
        }

        private static async Task<string[]> DatabaseBlackHashes()
        {
            try
            {
                using (HttpClient hc = new HttpClient())
                {
                    return (await hc.GetStringAsync("https://raw.githubusercontent.com/fabiodefilipposoftware/FDSec/refs/heads/main/Database/malwarehashes.txt")).Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);
                }
            }
            catch { }
            return null;
        }

        private static async Task<string[]> DatabaseWhiteHashes()
        {
            try
            {
                using (HttpClient hc = new HttpClient())
                {
                    return (await hc.GetStringAsync("https://raw.githubusercontent.com/fabiodefilipposoftware/FDSec/refs/heads/main/Database/whitelist.txt")).Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);
                }
            }
            catch { }
            return null;
        }

        private static async Task<string[]> DatabaseBlackIps()
        {
            try
            {
                using (HttpClient hc = new HttpClient())
                {
                    return (await hc.GetStringAsync("https://raw.githubusercontent.com/fabiodefilipposoftware/FDSec/refs/heads/main/Database/blackips.txt")).Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);
                }
            }
            catch { }
            return null;
        }

        private static async Task<bool> CheckSignature(string[] signatures, byte[] malwarebuffer)
        {
            string malwarehex = BitConverter.ToString(malwarebuffer).Replace("-", String.Empty);
            //Console.Error.WriteLineAsync("Malware hexdump\r\n" + malwarehex);
            foreach (string signature in signatures)
            {
                string hexsign = "^(?:" + signature.Replace("(", "(?=.*").Replace(" AND ", ")(?=.*").Replace(" OR ", "|") + ").*$";
                //Console.Error.WriteLineAsync("Pattern " + hexsign);
                if (Regex.IsMatch(malwarehex, hexsign, RegexOptions.Singleline | RegexOptions.Compiled | RegexOptions.IgnoreCase))
                {
                    return true;
                }
            }
            return false;
        }

        private static async Task<bool> CheckIpsByPid(HashSet<string> blackips, int pid)
        {
            HashSet<string> connectedIps = new HashSet<string>();
            int bufferSize = 0;
            GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, 2, 5);
            IntPtr tcpTablePtr = Marshal.AllocHGlobal(bufferSize);
            try
            {
                if (GetExtendedTcpTable(tcpTablePtr, ref bufferSize, true, 2, 5) == 0)
                {
                    int rowCount = Marshal.ReadInt32(tcpTablePtr);
                    IntPtr rowPtr = (IntPtr)((long)tcpTablePtr + 4);
                    for (int i = 0; i < rowCount; i++)
                    {
                        var row = Marshal.PtrToStructure<MibTcpRowOwnerPid>(rowPtr);
                        if (row.owningPid == pid && row.state == 5)
                        {
                            IPAddress remoteIp = new IPAddress(row.remoteAddr);
                            string ipString = remoteIp.ToString();
                            if (ipString != "127.0.0.1" && ipString != "0.0.0.0")
                            {
                                connectedIps.Add(ipString);
                            }
                        }
                        rowPtr = (IntPtr)((long)rowPtr + Marshal.SizeOf<MibTcpRowOwnerPid>());
                    }
                }
            }
            catch { }
            finally { Marshal.FreeHGlobal(tcpTablePtr); }
            foreach (string singleIp in connectedIps)
            {
                if (blackips.Contains(singleIp))
                {
                    Console.Error.WriteLineAsync("\r\nMALWARE CONNECTED to " + singleIp + " ...");
                    return true;
                }
            }
            return false;
        }

        private static async Task<bool> CheckMetadata(string malwarefilename)
        {
            try
            {
                X509Certificate bcert = X509Certificate.CreateFromSignedFile(malwarefilename);
                X509Certificate2 cert = new X509Certificate2(bcert);
                Console.Error.WriteLineAsync("\r\nsigned by " + cert.Subject);
                Console.Error.WriteLineAsync("\r\nissued from " + cert.Issuer);
                Console.Error.WriteLineAsync("\r\nvalid until " + cert.NotAfter);
                if (cert.Verify())
                {
                    Console.Error.WriteLineAsync("\r\nvalid signature!");
                    return true;
                }
            }
            catch
            {
                Console.Error.WriteLineAsync("\r\nINVALID signature!");
            }
            return false;
        }

        private static async Task<bool> CheckEntropy(byte[] malwarebuffer)
        {
            try
            {
                int[] counts = new int[256];
                foreach (byte b in malwarebuffer)
                    counts[b]++;

                double entropy = 0.0;
                int len = malwarebuffer.Length;
                if (len == 0) return false;
                for (int i = 0; i < 256; i++)
                {
                    if (counts[i] == 0)
                        continue;

                    double p = (double)counts[i] / len;
                    entropy -= p * Math.Log(p, 2);
                }
                Console.Error.WriteLineAsync("\r\nentropy = " + entropy.ToString());
                if (entropy > 6.5)
                {
                    return true;
                }
            }
            catch { }
            return false;
        }

        private static async Task GetQuarantine(string malwwarefilename)
        {
            File.Move(malwwarefilename, malwwarefilename + ".malware");
        }

        private static async Task<bool> FileValutation(string singlefile)
        {
            numfiles++;
            Console.Error.WriteAsync("\rScanned " + numfiles.ToString() + " files");
            byte[] malwarebuffer = File.ReadAllBytes(singlefile);
            string malwarehash = BitConverter.ToString(sha.ComputeHash(malwarebuffer)).Replace("-", String.Empty);
            if (!whitehashes.Contains(malwarehash))
            {
                if (blackhashes.Contains(malwarehash) || await CheckSignature(signatures, malwarebuffer))
                {
                    Console.Error.WriteLineAsync("\r\nMALWARE FOUND! " + singlefile);
                    return true;
                }
                else if (await CheckEntropy(malwarebuffer) && !await CheckMetadata(singlefile))
                {
                    Console.Error.WriteLineAsync("\r\nSuspicious file: " + singlefile);
                }
                else
                {
                    Console.Error.WriteLineAsync("\r\nNo malicious data: " + singlefile);
                }
            }
            else
            {
                Console.Error.WriteLineAsync("\r\nGOOD File! " + singlefile);
            }
            return false;
        }

        private static async Task ScanningDirectory(string singledirecotry)
        {
            try
            {
                foreach (string singlefile in Directory.GetFiles(singledirecotry))
                {
                    if (await FileValutation(singlefile))
                    {
                        GetQuarantine(singlefile);
                    }
                }

                foreach (string singledirectory in Directory.GetDirectories(singledirecotry))
                {
                    await ScanningDirectory(singledirectory);
                }
            }
            catch { }
        }

        private static string Sanitize(string input)
        {
            return new string(input.Where(c => c >= 32 && c <= 127).ToArray());
        }
        static async Task Main(string[] args)
        {
            Console.Error.WriteLine("loading database blackhashes...");
            blackhashes = new HashSet<string>(await DatabaseBlackHashes(), StringComparer.OrdinalIgnoreCase);
            Console.Error.WriteLine("loading database whitehashes...");
            whitehashes = new HashSet<string>(await DatabaseWhiteHashes(), StringComparer.OrdinalIgnoreCase);
            Console.Error.WriteLine("loading database blackIps...");
            blackIps = new HashSet<string>(await DatabaseBlackIps(), StringComparer.OrdinalIgnoreCase);
            Console.Error.WriteLine("loading dataset signatures...");
            signatures = await DatasetSignature();
            if (blackhashes != null && whitehashes != null && blackIps != null && signatures != null)
            {
                Console.Error.WriteLine(blackhashes.Count.ToString() + " blackhashes, " + whitehashes.Count.ToString() + " whitehashes, " + blackIps.Count + " blackIps and " + signatures.Length + " signatures");
                if (args.Length == 1)
                {
                    try
                    {
                        if (args[0].Length <= 260)
                        {
                            string argv = Sanitize(args[0]);
                            if (Directory.Exists(argv) && !File.Exists(argv))
                            {
                                ScanningDirectory(argv);
                            }
                            else if (File.Exists(argv))
                            {
                                if (await FileValutation(argv))
                                {
                                    GetQuarantine(argv);
                                }
                            }
                            else
                            {
                                Console.Error.WriteLine(argv + " does not exist!");
                            }
                        }
                    }
                    catch { }
                }
                else
                {
                    List<int> pid = new List<int>();
                    while (true)
                    {
                        // Scanning processes
                        foreach (Process proc in Process.GetProcesses())
                        {
                            if (proc.Id != Process.GetCurrentProcess().Id)
                            {
                                try
                                {
                                    if (!pid.Contains(proc.Id))
                                    {
                                        Console.Error.WriteLine("Scanning PID " + proc.Id);
                                        pid.Add(proc.Id);
                                        byte[] malwarebuffer = File.ReadAllBytes(proc.MainModule.FileName);
                                        if (malwarebuffer != null)
                                        {
                                            string malwarehash = BitConverter.ToString(sha.ComputeHash(malwarebuffer)).Replace("-", String.Empty);
                                            if (!whitehashes.Contains(malwarehash))
                                            {
                                                if (await FileValutation(proc.MainModule.FileName) || await CheckIpsByPid(blackIps, proc.Id))
                                                {
                                                    Process.Start(new ProcessStartInfo
                                                    {
                                                        FileName = "taskkill",
                                                        Arguments = $"/F /T /PID {proc.Id}",
                                                        CreateNoWindow = true,
                                                        UseShellExecute = false
                                                    }).WaitForExit();
                                                    GetQuarantine(proc.MainModule.FileName);
                                                }
                                            }
                                        }
                                    }
                                }
                                catch { }
                            }
                        }
                        for(int i = 0; i < pid.Count; i++)
                        {
                            try
                            {
                                if (Process.GetProcessById(pid[i]).HasExited)
                                {
                                    pid.Remove(i);
                                }
                            }
                            catch 
                            {}
                        }
                        Thread.Sleep(100);
                    }
                }
            }
        }
    }
}
