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
        private static readonly SHA256 sha = SHA256.Create();
        private static ulong numfiles = 0;
        private static readonly string radare2path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "bin", "radare2.exe");
        private static readonly string[] dangerousfncs = new string[] { 
            "RegCreateKeyEx", "RegDeleteKey", "RegEnumKeyEx", "RegOpenKeyEx", "RegSetValueEx",
            "VirtualAlloc", "VirtualFree", "VirtualProtect", "VirtualQuery", "CreateThread",
            "CreateProcess", "CreateMutex", "TerminateThread", "MapViewOfFile", "UnmapViewOfFile",
            "socket", "connect", "send", "recv", "shutdown", "closesocket",
            "inet_addr", "inet_ntoa", "inet_pton", "htons", "gethostbyname",
            "InternetOpen", "InternetConnect", "HttpOpenRequest", "HttpSendRequest", "InternetReadFile",
            "InternetCloseHandle", "InternetCrackUrl", "HttpQueryInfo", "WriteFile", "SetFilePointer",
            "CreateToolHelp32Snapshot", "Process32First", "Process32Next", "CreateFile", "ReadFile",
            "MoveFileEx", "FindFirstFile", "FindNextFile", "FindClose", "GetFileSize",
            "CryptAcquireContext", "CryptGenKey", "CryptGenRandom", "CryptEncrypt", "CryptDecrypt",
            "CryptImportKey", "CryptExportKey", "CryptDestroyKey", "CryptReleaseContext", "LookupAccountSid",
            "LsaAddAccountRights", "LsaConnectUntrusted", "InitializeSecurityDescriptor", "EqualDomainSid",
            "WNetOpenEnum", "WNetEnumResource", "WNetAddConnection2", "WNetCloseEnum", "GetTickCount", 
            "QueryPerformanceCounter", "Sleep", "IsProcessorFeaturePresent", "GetProcAddress", "FreeLibrary",
            "GetModuleHandle", "IsDebuggerPresent", "FlushInstructionCache", "TerminateProcess", "GetCurrentProcess",
            "GetCurrentThreadId", "WinHttpOpen", "WinHttpConnect", "WinHttpOpenRequest", "WinHttpSendRequest",
            "WinHttpReceiveResponse", "WinHttpReadData", "WinHttpQueryHeaders", "WinHttpCrackUrl", "WinHttpCloseHandle",
            "WinHttpSetTimeouts", "GetFileAttributesEx", "GetComputerName", "GetLogicalDrives", "GlobalMemoryStatusEx",
            "GetDiskFreeSpaceEx", "GetTempPath", "GetTimeZoneInformation"};
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
                else if (!await CheckMetadata(malwarebuffer) && await CheckFnc(singlefile) && await CheckEntropy(singlefile))
                {
                    Console.Error.WriteLineAsync("\r\nMALWARE FOUND! " + singlefile);
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
        
        private static async Task<bool> CheckFnc(string singlefile)
        {

            if (File.Exists(radare2path))
            {
                Process radare2 = new Process();
                ProcessStartInfo si = new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = $"/c " + radare2path + " -q -e bin.relocs.apply=true -e anal.jmptbl.split=true -c \"e scr.color=0; aaa; iih\" \"" + singlefile + "\"",
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardOutput = true
                };
                radare2.StartInfo = si;
                radare2.Start();
                string[] functions = radare2.StandardOutput.ReadToEnd().Split();
                uint matches = 0;
                foreach (string function in functions)
                {
                    foreach (string dangerousfnc in dangerousfncs)
                    {
                        if (function.Contains(dangerousfnc))
                        {
                            matches++;
                        }

/*
uint codeinjection = 0, sysregpersistance = 0, dataexfiltration = 0, httpdataexfiltration = 0, filecryptography = 0, antidbg = 0, envdetection = 0, antisandbox = 0, infostealer = 0, worming = 0;

if (function.Contains(dangerousfnc))
{
   select (dangerousfnc)
   {
      case "VirtualAlloc":
      case "VirtualProtect":
      case "WriteFile":
      case "RtlMoveMemory":
      case "WriteProcessMemory":
         codeinjection++;
      break;

      case "RegOpenKeyEx":
      case "RegCreateKeyEx"
      case "RegSetValueEx":
         sysregpersistance++;
      break;

      case "socket"
      case "connect"
      case "send"
         dataexfiltration++;
      break;

      case "InternetOpen":
      case "InternetConnect":
      case "HttpOpenRequest":
      case "HttpSendRequest":
      case "InternetReadFile":
         httpdataexfiltration++;
      break;

      case "FindFirstFile":
      case "FindNextFile":
      case "CreateFile":
      case "ReadFile":
      case "CryptEncrypt":
      case "WriteFile":
         filecryptography++;
      break;

      case "IsDebuggerPresent":
      case "TerminateProcess":
         antidbg++;
      break;

      case "QueryPerformanceCounter":
      case "GetTickCount":
      case "Sleep":
         antisandbox++;
      break;

      case "GlobalMemoryStatusEx":
      case "GetDiskFreeSpaceEx":
         envdetection++;
      break;

      case "GetComputerName":
      case "GetLogicalDrives":
      case "GetTempPath":
      case "LookupAccountSid":
         infostealer++;
      break;

      case "WNetOpenEnum":
      case "WNetEnumResource":
      case "WNetAddConnection2":
         worming++;
      break;
   }

   Array.Clear(functions, 0, functions.Length);

   if ((codeinjection + sysregpersistance + dataexfiltration + httpdataexfiltration + filecryptography + antidbg + envdetection + antisandbox + infostealer + worming) > 8)
   {
      codeinjection = 0;
      sysregpersistance = 0;
      dataexfiltration = 0;
      httpdataexfiltration = 0;
      filecryptography = 0; antidbg = 0;
      envdetection = 0;
      antisandbox = 0;
      infostealer = 0;
      worming = 0;
      return true;
   }
}
*/
                    }
                }
                Array.Clear(functions, 0, functions.Length);
                if (matches >= 8)
                {
                    matches = 0;
                    return true;
                }
                Console.Error.WriteLineAsync(matches.ToString() + " functions found!");
                radare2.Dispose();
            }
            else
            {
                Console.Error.WriteLine("radare2 not found!");
            }
            return false;
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
                            argv = String.Empty;
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
                                            malwarehash = String.Empty;
                                        }
                                        Array.Clear(malwarebuffer, 0, malwarebuffer.Length);
                                    }
                                }
                                catch { }
                            }
                        }
                        for (int i = 0; i < pid.Count; i++)
                        {
                            try
                            {
                                if (Process.GetProcessById(pid[i]).HasExited)
                                {
                                    pid.Remove(i);
                                }
                            }
                            catch
                            { }
                        }
                        Thread.Sleep(100);
                    }
                }
            }
            blackhashes.Clear();
            whitehashes.Clear();
            blackIps.Clear();
            Array.Clear(signatures, 0, signatures.Length);
        }
    }
}




