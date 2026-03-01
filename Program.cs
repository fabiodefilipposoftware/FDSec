using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace FDSec
{
    internal class Program
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct MibTcpRowOwnerPid
        {
            public uint state;
            public uint locaAddr;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)] public byte[] localPort;
            public uint remoteAddr;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)] public byte[] remotePort;
            public int owningPid;
        }

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int dwOutBufLen, bool sort, int ipVersion, int tblClass, uint reserved = 0);

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
            string malwarehex = BitConverter.ToString(malwarebuffer).Replace("-", String.Empty).ToLower();
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
                if(blackips.Contains(singleIp))
                {
                    Console.Error.WriteLineAsync("MALWARE CONNECTED to "+ singleIp+" ...");
                    return true;
                }
            }
            return false;
        }

        static async Task Main(string[] args)
        {
            using (SHA256 sha = SHA256.Create())
            {
                Console.Error.WriteLine("loading database blackhashes...");
                HashSet<string> blackhashes = new HashSet<string>(await DatabaseBlackHashes(), StringComparer.OrdinalIgnoreCase);
                Console.Error.WriteLine("loading database whitehashes...");
                HashSet<string> whitehashes = new HashSet<string>(await DatabaseWhiteHashes(), StringComparer.OrdinalIgnoreCase);
                Console.Error.WriteLine("loading database blackIps...");
                HashSet<string> blackIps = new HashSet<string>(await DatabaseBlackIps(), StringComparer.OrdinalIgnoreCase);
                Console.Error.WriteLine("loading dataset signatures...");
                string[] signatures = await DatasetSignature();
                if (blackhashes != null && signatures != null)
                {
                    Console.Error.WriteLine("Start!");
                    Console.Error.WriteLine(blackhashes.Count.ToString() + " blackhashes, " + whitehashes.Count.ToString() + " whitehashes, " + blackIps.Count + " blackIps and " + signatures.Length + " signatures");
                    if (args.Length == 1)
                    {
                        try
                        {
                            if (File.Exists(args[0]))
                            {
                                byte[] malwarebuffer = File.ReadAllBytes(args[0]);
                                string malwarehash = BitConverter.ToString(sha.ComputeHash(malwarebuffer)).Replace("-", String.Empty);
                                if (!whitehashes.Contains(malwarehash))
                                {
                                    if (blackhashes.Contains(malwarehash) || await CheckSignature(signatures, malwarebuffer))
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
                                else
                                {
                                    Console.Error.WriteLine("GOOD File! " + args[0]);
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
                                            string malwarehash = BitConverter.ToString(sha.ComputeHash(malwarebuffer)).Replace("-", String.Empty);
                                            if (!whitehashes.Contains(malwarehash))
                                            {
                                                Task<bool> checkips = Task.Run(() => CheckIpsByPid(blackIps, proc.Id));
                                                Task<bool> checkhash = Task.Run(() => blackhashes.Contains(malwarehash));
                                                Task<bool> checksignature = Task.Run(() => CheckSignature(signatures, malwarebuffer));
                                                Task<bool> result = await Task.WhenAny(new List<Task<bool>> {checkhash, checksignature, checkips });
                                                if (await result)
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
}
