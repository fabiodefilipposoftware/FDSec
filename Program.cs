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
using System.ServiceProcess;
using System.Security.Principal;

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

        private static ulong numfiles = 0;

        private static readonly string radare2path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "bin", "radare2.exe");
        private static readonly string[] ransomwords = new string[] {
            "important files have been encrypted",
            "your files have been encrypted",
            "private key and decryption program",
            "how I can recovery my files?",
            "your network is under our full control",
            "your network has been penetrated",
            "YOUR FILES ARE ENCRYPTED AND LEAKED",
            "all your files are now encrypted and inaccessible",
            "to RESTORE all of your files, please follow this simple steps",
            "your files, documents, photos, databases and other important files are encrypted",
            "backups and shadow copies also encrypted or removed",
            "all of your files are currently encrypted by",
            "your network has been locked", ".onion"};
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

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        private const uint TOKEN_QUERY = 0x0008;
                
        private static bool CheckServiceStatus(string serviceName)
        {
            try
            {
                if (new ServiceController(serviceName).Status == ServiceControllerStatus.Running)
                {
                    return true;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Errore durante il controllo di {serviceName}: {ex.Message}");
            }
            return false;
        }

        private static bool isAdmin(Process process)
        {
            IntPtr tokenHandle = IntPtr.Zero;
            try
            {
               if (OpenProcessToken(process.Handle, TOKEN_QUERY, out tokenHandle))
               {
                   using (WindowsIdentity identity = new WindowsIdentity(tokenHandle))
                   {
                       WindowsPrincipal principal = new WindowsPrincipal(identity);
                       return principal.IsInRole(WindowsBuiltInRole.Administrator);
                   }
               }
            }
            catch (Exception ex)
            {
                 Console.Error.WriteLineAsync(ex.Message);
            }
            finally
            {
                if (tokenHandle != IntPtr.Zero)
                {
                   CloseHandle(tokenHandle);
                }
            }
            return false;
        }

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
                    //return (await hc.GetStringAsync("https://myip.ms/files/blacklist/general/latest_blacklist.txt")).Split(new[] { '\n', '\r', '#' }, StringSplitOptions.RemoveEmptyEntries);
                }
            }
            catch { }
            return null;
        }

        private static bool CheckSignature(string malwarehex)
        {
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

        private static bool CheckIpsByPid(HashSet<string> blackips, int pid)
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
            foreach (string singleIpv in connectedIps)
            {
                string singleIp = singleIpv.Trim(new[] { '\t', ' ' });
                if (!String.IsNullOrEmpty(singleIp))
                {
                    if (blackips.Contains(singleIp))
                    {
                        Console.Error.WriteLineAsync("\r\nMALWARE CONNECTED to " + singleIp + " ...");
                        return true;
                    }
                }
            }
            return false;
        }

        private static bool CheckMetadata(string malwarefilename)
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

        private static bool CheckEntropy(byte[] malwarebuffer)
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

        private static void GetQuarantine(string malwwarefilename)
        {
            File.Move(malwwarefilename, malwwarefilename + ".malware");
        }

        private static bool FileValutation(string singlefile)
        {
            numfiles++;
            SHA256 sha = SHA256.Create();
            Console.Error.WriteAsync("\rScanned " + numfiles.ToString() + " files");
            byte[] malwarebuffer = File.ReadAllBytes(singlefile);
            string malwarehex = BitConverter.ToString(malwarebuffer).Replace("-", String.Empty);
            string malwarehash = BitConverter.ToString(sha.ComputeHash(malwarebuffer)).Replace("-", String.Empty);
            if (!whitehashes.Contains(malwarehash))
            {
                if (blackhashes.Contains(malwarehash))
                {
                    malwarehash = String.Empty;
                    malwarehex = String.Empty;
                    Array.Clear(malwarebuffer, 0, malwarebuffer.Length);
                    Console.Error.WriteLineAsync("\r\nMALWARE FOUND! " + singlefile);
                    return true;
                }
                else if ( CheckFnc(singlefile))
                {
                    malwarehash = String.Empty;
                    malwarehex = String.Empty;
                    Array.Clear(malwarebuffer, 0, malwarebuffer.Length);
                    Console.Error.WriteLineAsync("\r\nMALWARE FOUND! " + singlefile);
                    return true;
                }
                else if (! CheckMetadata(singlefile) &&  CheckEntropy(malwarebuffer))
                {
                    malwarehash = String.Empty;
                    malwarehex = String.Empty;
                    Array.Clear(malwarebuffer, 0, malwarebuffer.Length);
                    Console.Error.WriteLineAsync("\r\nsuspicious file: " + singlefile);
                    return true;
                }
                else if ( CheckSignature(malwarehex))
                {
                    malwarehash = String.Empty;
                    malwarehex = String.Empty;
                    Array.Clear(malwarebuffer, 0, malwarebuffer.Length);
                    Console.Error.WriteLineAsync("\r\nMALWARE FOUND! " + singlefile);
                    return true;
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
            malwarehash = String.Empty;
            malwarehex = String.Empty;
            Array.Clear(malwarebuffer, 0, malwarebuffer.Length);
            return false;
        }

        private static async Task ScanningDirectory(string singledirecotry)
        {
            try
            {
                Parallel.ForEach(Directory.GetFiles(singledirecotry), new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount }, singlefile =>
                {
                    try
                    {
                        if (FileValutation(singlefile))
                        {
                            GetQuarantine(singlefile);
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.Error.WriteLine($"Errore su {singlefile}: {ex.Message}");
                    }
                });

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

        private static bool CheckFnc(string singlefile)
        {
            uint codeinjection = 0, sysregpersistance = 0, dataexfiltration = 0, httpdataexfiltration = 0, filecryptography = 0, antidbg = 0, envdetection = 0, antisandbox = 0, infostealer = 0, worming = 0;

            if (File.Exists(radare2path))
            {
                Process radare2 = new Process();
                radare2.StartInfo = new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = $"/c " + radare2path + " -q -e bin.relocs.apply=true -e anal.jmptbl.split=true -c \"e scr.color=0; aaa; iih\" \"" + singlefile + "\"",
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardOutput = true
                };
                radare2.Start();
                radare2.BeginOutputReadLine();
                Process redare2Id = Process.GetProcessById(radare2.Id);
                if (!radare2.WaitForExit(5000))
                {
                    Process.Start(new ProcessStartInfo
                    {
                        FileName = "taskkill",
                        Arguments = $"/F /T /PID {radare2.Id}",
                        CreateNoWindow = true,
                        UseShellExecute = false
                    }).Start();
                }
                string[] functions = radare2.StandardOutput.ReadToEnd().Split();
                if (functions.Length == 0)
                {
                    Console.Error.WriteLineAsync("functions not found");
                    return false;
                }
                foreach (string function in functions)
                {
                    foreach (string dangerousfnc in dangerousfncs)
                    {
                        if (function.Contains(dangerousfnc))
                        {
                            switch (dangerousfnc)
                            {
                                case "VirtualAlloc":
                                case "VirtualProtect":
                                //case "WriteFile":
                                case "RtlMoveMemory":
                                case "WriteProcessMemory":
                                    codeinjection++;
                                    break;

                                case "RegOpenKeyEx":
                                case "RegCreateKeyEx":
                                case "RegSetValueEx":
                                    sysregpersistance++;
                                    break;

                                case "socket":
                                case "connect":
                                case "send":
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
                            radare2.Dispose();
                        }
                    }
                }
            }
            else
            {
                Console.Error.WriteLine("radare2 not found!\r\nsearching functions from strings");

                string testomalware = File.ReadAllText(singlefile);
                uint riskscore = 0;
                foreach (string sransomwords in ransomwords)
                {
                    if (testomalware.IndexOf(sransomwords, StringComparison.OrdinalIgnoreCase) > -1)
                    {
                        riskscore++;
                    }
                }

                if (riskscore > 1)
                {
                    return true;
                }

                foreach (string dangerousfnc in dangerousfncs)
                {
                    if (testomalware.Contains(dangerousfnc))
                    {
                        switch (dangerousfnc)
                        {
                            case "VirtualAlloc":
                            case "VirtualProtect":
                            //case "WriteFile":
                            case "RtlMoveMemory":
                            case "WriteProcessMemory":
                                codeinjection++;
                                break;

                            case "RegOpenKeyEx":
                            case "RegCreateKeyEx":
                            case "RegSetValueEx":
                                sysregpersistance++;
                                break;

                            case "socket":
                            case "connect":
                            case "send":
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
                    }
                }
            }
            ulong matches = (codeinjection + sysregpersistance + dataexfiltration + httpdataexfiltration + filecryptography + antidbg + envdetection + antisandbox + infostealer + worming);
            if (matches > 8)
            {
                Console.Error.WriteLine(matches.ToString() + " API FOUND!");
                codeinjection = 0;
                sysregpersistance = 0;
                dataexfiltration = 0;
                httpdataexfiltration = 0;
                filecryptography = 0;
                antidbg = 0;
                envdetection = 0;
                antisandbox = 0;
                infostealer = 0;
                worming = 0;
                matches = 0;
                return true;
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
                                if (FileValutation(argv))
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
                    SHA256 sha = SHA256.Create();
                    while (true)
                    {
                        // Scanning processes
                        foreach (Process proc in Process.GetProcesses())
                        {
                            if (proc.Id != Process.GetCurrentProcess().Id)
                            {
                                if (!CheckServiceStatus("EventLog") && !CheckServiceStatus("VSS"))
                                {
                                    if (isAdmin(proc))
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
                                else
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
                                                    if (FileValutation(proc.MainModule.FileName) || CheckIpsByPid(blackIps, proc.Id))
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
                        Thread.Sleep(150);
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
