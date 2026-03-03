using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq.Expressions;
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
                    Console.Error.WriteLineAsync("MALWARE CONNECTED to " + singleIp + " ...");
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
                Console.Error.WriteLineAsync("signed by " + cert.Subject);
                Console.Error.WriteLineAsync("issued from " + cert.Issuer);
                Console.Error.WriteLineAsync("valid until " + cert.NotAfter);
                if (cert.Verify())
                {
                    Console.Error.WriteLineAsync("firma valida");
                    return true;
                }
            }
            catch{}
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
                if (entropy > 6.5)
                {
                    return true;
                }
            }
            catch{}
            return false;
        }

        private static async Task GetQuarantine(string malwwarefilename)
        {
            File.Move(malwwarefilename, malwwarefilename + ".malware");
        }

        private static async Task<bool> FileValutation(string singlefile)
        {
            byte[] malwarebuffer = File.ReadAllBytes(singlefile);
            string malwarehash = BitConverter.ToString(sha.ComputeHash(malwarebuffer)).Replace("-", String.Empty);
            if (!whitehashes.Contains(malwarehash))
            {
                if (blackhashes.Contains(malwarehash) || (await CheckSignature(signatures, malwarebuffer) && await CheckEntropy(malwarebuffer) && await CheckMetadata(singlefile)))
                {
                    Console.Error.WriteLine("MALWARE FOUND! " + singlefile);
                    /*Process.Start(new ProcessStartInfo
                    {
                        FileName = "cmd.exe",
                        Arguments = $"/c tar -acf quarantine.zip {args[0]} && del {args[0]}",
                        CreateNoWindow = true,
                        UseShellExecute = false
                    }).WaitForExit();*/
                    return true;
                }
                else
                {
                    Console.Error.WriteLine("No malicious data: " + singlefile);
                }
            }
            else
            {
                Console.Error.WriteLine("GOOD File! " + singlefile);
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
                Console.Error.WriteLine("Start!");
                Console.Error.WriteLine(blackhashes.Count.ToString() + " blackhashes, " + whitehashes.Count.ToString() + " whitehashes, " + blackIps.Count + " blackIps and " + signatures.Length + " signatures");
                if (args.Length == 1)
                {
                    try
                    {
                        if (Directory.Exists(args[0]) && !File.Exists(args[0]))
                        {
                            ScanningDirectory(args[0]);
                        }
                        else if (File.Exists(args[0]))
                        {
                            if(await FileValutation(args[0]))
                            {
                                GetQuarantine(args[0]);
                            }
                            /*byte[] malwarebuffer = File.ReadAllBytes(args[0]);
                            string malwarehash = BitConverter.ToString(sha.ComputeHash(malwarebuffer)).Replace("-", String.Empty);
                            if (!whitehashes.Contains(malwarehash))
                            {
                                if (blackhashes.Contains(malwarehash) || await CheckSignature(signatures, malwarebuffer))
                                {
                                    Console.Error.WriteLine("MALWARE FOUND! " + args[0]);
                                    /*Process.Start(new ProcessStartInfo
                                    {
                                        FileName = "cmd.exe",
                                        Arguments = $"/c tar -acf quarantine.zip {args[0]} && del {args[0]}",
                                        CreateNoWindow = true,
                                        UseShellExecute = false
                                    }).WaitForExit();
                                    GetQuarantine(args[0]);
                                }
                            }
                            else
                            {
                                Console.Error.WriteLine("GOOD File! " + args[0]);
                            }*/
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
                                        string malwarehash = BitConverter.ToString(sha.ComputeHash(malwarebuffer)).Replace("-", String.Empty);
                                        if (!whitehashes.Contains(malwarehash))
                                        {
                                            /*Task<bool> checkips = Task.Run(() => CheckIpsByPid(blackIps, proc.Id));
                                            Task<bool> checkhash = Task.Run(() => blackhashes.Contains(malwarehash));
                                            Task<bool> checksignature = Task.Run(() => CheckSignature(signatures, malwarebuffer));
                                            Task<bool> result = await Task.WhenAny(new List<Task<bool>> { checkhash, checksignature, checkips });
                                            if (await result)
                                            {
                                                Process.Start(new ProcessStartInfo
                                                {
                                                    FileName = "taskkill",
                                                    Arguments = $"/F /T /PID {proc.Id}", //&& tar -acf quarantine.zip {proc.MainModule.FileName} && del {proc.MainModule.FileName}",
                                                    CreateNoWindow = true,
                                                    UseShellExecute = false
                                                }).WaitForExit();
                                                GetQuarantine(proc.MainModule.FileName);
                                            }*/
                                            if (await FileValutation(proc.MainModule.FileName) && await CheckIpsByPid(blackIps, proc.Id))
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
                                catch { }
                            }
                        }
                        Thread.Sleep(250);
                    }
                }
            }
        }
    }
}

