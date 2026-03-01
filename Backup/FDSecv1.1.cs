using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace FDSec
{
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
            catch { }
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
                                byte[] malwarebuffer = File.ReadAllBytes(args[0]);
                                string malwarehash = BitConverter.ToString(sha.ComputeHash(malwarebuffer)).Replace("-", String.Empty).ToLower();
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
                                            if (blackhashes.Contains(malwarehash) || await CheckSignature(signatures, malwarebuffer))
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
    }
}

