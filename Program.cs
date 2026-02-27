using System;
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
                    return (await hc.GetStringAsync("dataseturl")).Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);
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

        private static async Task<bool> CheckSignature(string[] signatures, string malwarebuffer)
        {
            foreach(string signature in signatures)
            {
                string hexsign = "^" + signature.Replace("(", "(?:(?=.*").Replace(" AND ", ")(?=.*").Replace(" OR ", "|");
                if(Regex.IsMatch(malwarebuffer, hexsign, RegexOptions.Singleline | RegexOptions.Compiled | RegexOptions.Compiled))
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
                string[] blackhashes = await DatabaseHashes();
                string[] signatures = await DatasetSignature();
                if(blackhashes != null && signatures != null)
                {
                    if (args.Length == 1)
                    {
                        try
                        {
                            if (File.Exists(args[0]))
                            {
                                string malwarehash = BitConverter.ToString(sha.ComputeHash(File.ReadAllBytes(args[0]))).Replace("-", String.Empty).ToLower();
                                if (Array.IndexOf(blackhashes, malwarehash) > -1)
                                {
                                    File.Delete(args[0]);
                                }
                            }
                        }
                        catch { }
                    }
                    else
                    {
                        while (true)
                        {
                            foreach (var proc in Process.GetProcesses())
                            {
                                if (proc.Id != Process.GetCurrentProcess().Id)
                                {
                                    try
                                    {
                                        byte[] malwarebuffer = File.ReadAllBytes(proc.MainModule.FileName);
                                        if (malwarebuffer != null)
                                        {
                                            string malwarehex = BitConverter.ToString(malwarebuffer).Replace("-", String.Empty);
                                            string malwarehash = BitConverter.ToString(sha.ComputeHash(malwarebuffer)).Replace("-", String.Empty).ToLower();
                                            if (Array.IndexOf(blackhashes, malwarehash) > -1 || await CheckSignature(signatures, malwarehex))
                                            {
                                                ProcessStartInfo startInfo = new ProcessStartInfo
                                                {
                                                    FileName = "cmd.exe",
                                                    Arguments = "/c taskkill /F /T /PID " + proc.Id.ToString() + " && tar -acf quarantine.zip " + proc.MainModule.FileName + " && del " + proc.MainModule.FileName,
                                                    CreateNoWindow = true,
                                                    UseShellExecute = false,
                                                    WindowStyle = ProcessWindowStyle.Hidden
                                                };
                                                Process.Start(startInfo);
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

