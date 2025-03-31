using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.Sockets;
using System.Net.NetworkInformation;
using Microsoft.Win32;
using System.Text;
using System.Security.Principal;
using System.Runtime.InteropServices;
using Tftp.Net;

namespace SystemInfoCollector
{
    // 1. 首先定义所有枚举类型
    public enum TransferProtocol
    {
        FTP,
        SMB,
        TFTP
    }

    // 2. 定义所有配置类
    #region 配置数据模型
    class FtpConfig
    {
        public string Host { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public string RemotePath { get; set; }
    }

    class SmbConfig
    {
        public SmbConfig()
        {
            ShareName = "C$";
        }

        public string Server { get; set; }
        public string ShareName { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
    }

    class TftpConfig
    {
        public TftpConfig()
        {
            Server = "192.168.1.100";
        }

        public string Server { get; set; }
    }

    class TransferConfig
    {
        public TransferConfig()
        {
            Ftp = new FtpConfig();
            Smb = new SmbConfig();
            Tftp = new TftpConfig();
        }

        public TransferProtocol Protocol { get; set; }
        public FtpConfig Ftp { get; set; }
        public SmbConfig Smb { get; set; }
        public TftpConfig Tftp { get; set; }
    }
    #endregion

    // 3. 定义系统信息数据模型
    #region 系统信息模型
    class NetworkAdapter
    {
        public NetworkAdapter()
        {
            IPAddresses = new List<string>();
        }

        public string Name { get; set; }
        public string Type { get; set; }
        public string MAC { get; set; }
        public List<string> IPAddresses { get; set; }
    }

    class PhysicalDisk
    {
        public string Model { get; set; }
        public string Type { get; set; }
        public double SizeGB { get; set; }
    }

    class SystemInfo
    {
        public SystemInfo()
        {
            PhysicalDisks = new List<PhysicalDisk>();
            NetworkAdapters = new List<NetworkAdapter>();
        }

        public string ComputerName { get; set; }
        public string SystemType { get; set; }
        public string OSVersion { get; set; }
        public string CpuInfo { get; set; }
        public double TotalMemoryGB { get; set; }
        public List<PhysicalDisk> PhysicalDisks { get; set; }
        public List<NetworkAdapter> NetworkAdapters { get; set; }
    }
    #endregion

    // 4. 主程序类
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("=== 系统信息收集工具 ===");
            Console.WriteLine("版本：3.1 (最终稳定版)\n");

            if (args.Length == 0)
            {
                Console.WriteLine("提示: 使用 --help 查看命令行选项\n");
            }

            var config = new TransferConfig();
            ParseCommandLineArgs(args, config);

            var systemInfo = CollectSystemInfo();
            var fileName = GenerateFileName(systemInfo.ComputerName);
            var localPath = SaveToCsv(systemInfo, fileName);

            if (config.Protocol != default(TransferProtocol))
            {
                TransferFile(config, localPath);
            }
            else
            {
                Console.WriteLine("\n提示: 未指定传输协议，文件仅保存在本地");
            }
            
            Console.WriteLine("\n操作完成。文件已保存到: " + localPath);
            Console.WriteLine("按任意键退出...");
            Console.ReadKey();
        }

        #region 核心功能
        static SystemInfo CollectSystemInfo()
        {
            Console.WriteLine(">>> 正在收集系统信息...");

            try
            {
                var info = new SystemInfo
                {
                    ComputerName = Environment.MachineName,
                    SystemType = Environment.Is64BitOperatingSystem ? "64-bit" : "32-bit",
                    OSVersion = GetOSVersion(),
                    CpuInfo = GetCpuInfo(),
                    TotalMemoryGB = GetTotalMemoryGB(),
                    PhysicalDisks = GetPhysicalDisks(),
                    NetworkAdapters = GetNetworkAdapters()
                };

                PrintSystemInfo(info);
                return info;
            }
            catch (Exception ex)
            {
                Console.WriteLine("收集系统信息时发生严重错误: " + ex.Message);
                return new SystemInfo
                {
                    ComputerName = "ERROR",
                    OSVersion = "信息收集失败: " + ex.Message
                };
            }
        }

        static void TransferFile(TransferConfig config, string localPath)
        {
            Console.WriteLine("\n>>> 正在传输文件...");
            bool result = false;

            try
            {
                switch (config.Protocol)
                {
                    case TransferProtocol.FTP:
                        result = FtpTransfer(localPath, config.Ftp);
                        break;
                    case TransferProtocol.SMB:
                        result = SmbTransfer(localPath, config.Smb);
                        break;
                    case TransferProtocol.TFTP:
                        result = TftpTransfer(localPath, config.Tftp);
                        break;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("传输错误: " + ex.Message);
            }

            Console.WriteLine(result ? "√ 传输成功" : "× 传输失败");
        }
        #endregion

        #region 信息收集方法
        static string GetOSVersion()
        {
            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion"))
                {
                    if (key != null)
                    {
                        var product = key.GetValue("ProductName") as string ?? "Windows";
                        var version = key.GetValue("DisplayVersion") as string ?? "";
                        var build = key.GetValue("CurrentBuildNumber") as string ?? "";

                        var osInfo = new StringBuilder(product);
                        if (!string.IsNullOrEmpty(version)) osInfo.Append(" " + version);
                        if (!string.IsNullOrEmpty(build)) osInfo.Append(" (Build " + build + ")");
                        return osInfo.ToString();
                    }
                }
            }
            catch { }
            return Environment.OSVersion.ToString();
        }

        static string GetCpuInfo()
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT Name FROM Win32_Processor"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        return obj["Name"] != null ? 
                            obj["Name"].ToString().Trim() : "N/A";
                    }
                }
            }
            catch { }
            return "N/A";
        }

        static double GetTotalMemoryGB()
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT TotalPhysicalMemory FROM Win32_ComputerSystem"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        if (obj["TotalPhysicalMemory"] != null)
                        {
                            return Math.Round(
                                Convert.ToUInt64(obj["TotalPhysicalMemory"]) / 
                                1073741824.0, 2);
                        }
                    }
                }
            }
            catch { }
            return 0;
        }

        static List<PhysicalDisk> GetPhysicalDisks()
        {
            var disks = new List<PhysicalDisk>();
            try
            {
                using (var searcher = new ManagementObjectSearcher(
                    "SELECT Model, Size, MediaType FROM Win32_DiskDrive"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        var model = obj["Model"] != null ? 
                            obj["Model"].ToString().Trim() : "Unknown";
                        var mediaType = obj["MediaType"] != null ? 
                            obj["MediaType"].ToString() : "";
                        var size = obj["Size"] != null ? 
                            Convert.ToUInt64(obj["Size"]) : 0UL;

                        disks.Add(new PhysicalDisk
                        {
                            Model = model,
                            Type = mediaType.Contains("SSD") ? "SSD" : "HDD",
                            SizeGB = Math.Round(size / 1073741824.0, 2)
                        });
                    }
                }
            }
            catch { }
            return disks.Where(d => d.SizeGB > 0).ToList();
        }

        static List<NetworkAdapter> GetNetworkAdapters()
        {
            var adapters = new List<NetworkAdapter>();
            try
            {
                foreach (var nic in NetworkInterface.GetAllNetworkInterfaces()
                    .Where(n => n.OperationalStatus == OperationalStatus.Up &&
                               n.NetworkInterfaceType != NetworkInterfaceType.Loopback))
                {
                    var adapter = new NetworkAdapter
                    {
                        Name = nic.Name,
                        Type = nic.NetworkInterfaceType.ToString(),
                        MAC = FormatMacAddress(nic.GetPhysicalAddress().ToString()),
                        IPAddresses = GetIpAddresses(nic)
                    };
                    adapters.Add(adapter);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("获取网卡信息错误: " + ex.Message);
            }
            return adapters;
        }

        static string FormatMacAddress(string rawMac)
        {
            if (string.IsNullOrEmpty(rawMac) || rawMac.Length < 12)
                return "N/A";

            return string.Join(":",
                Enumerable.Range(0, 6)
                .Select(i => rawMac.Substring(i * 2, 2)));
        }

        static List<string> GetIpAddresses(NetworkInterface nic)
        {
            var ips = new List<string>();
            try
            {
                foreach (var ip in nic.GetIPProperties().UnicastAddresses
                    .Where(addr => addr.Address.AddressFamily == AddressFamily.InterNetwork ||
                                  addr.Address.AddressFamily == AddressFamily.InterNetworkV6))
                {
                    ips.Add(ip.Address.ToString());
                }
            }
            catch { }
            return ips;
        }
        #endregion

        #region 输出方法
        static void PrintSystemInfo(SystemInfo info)
        {
            Console.WriteLine("\n=== 系统信息汇总 ===");
            Console.WriteLine("计算机名称: " + info.ComputerName);
            Console.WriteLine("系统架构: " + info.SystemType);
            Console.WriteLine("操作系统: " + info.OSVersion);
            Console.WriteLine("CPU信息: " + info.CpuInfo);
            Console.WriteLine("总内存: {0:0.00} GB", info.TotalMemoryGB);

            Console.WriteLine("\n[存储设备]");
            foreach (var disk in info.PhysicalDisks)
            {
                Console.WriteLine("  - {0} ({1}): {2:0.00} GB", 
                    disk.Model, disk.Type, disk.SizeGB);
            }

            Console.WriteLine("\n[网络适配器]");
            foreach (var adapter in info.NetworkAdapters)
            {
                Console.WriteLine("  - {0} ({1})", adapter.Name, adapter.Type);
                Console.WriteLine("    MAC地址: " + adapter.MAC);
                Console.WriteLine("    IP地址: " + string.Join(", ", adapter.IPAddresses));
            }
        }

        static string GenerateFileName(string computerName)
        {
            return string.Format("{0}_SystemInfo_{1:yyyyMMdd_HHmmss}.csv",
                computerName, DateTime.Now);
        }

        static string SaveToCsv(SystemInfo info, string fileName)
        {
            try
            {
                var directory = AppDomain.CurrentDomain.BaseDirectory;
                var path = Path.Combine(directory, fileName);
                
                Directory.CreateDirectory(directory);

                var csv = new StringBuilder();
                csv.AppendLine("ComputerName,SystemType,OSVersion,CPUInfo,TotalMemoryGB,Disks,NetworkAdapters");

                var diskInfo = new StringBuilder();
                foreach (var disk in info.PhysicalDisks)
                {
                    diskInfo.Append(string.Format("[{0}|{1}|{2:0.00}GB];",
                        disk.Model, disk.Type, disk.SizeGB));
                }

                var networkInfo = new StringBuilder();
                foreach (var adapter in info.NetworkAdapters)
                {
                    networkInfo.Append(string.Format("[{0}|{1}|{2}|{3}];",
                        adapter.Name,
                        adapter.Type,
                        adapter.MAC,
                        string.Join(";", adapter.IPAddresses)));
                }

                csv.AppendLine(string.Format("\"{0}\",\"{1}\",\"{2}\",\"{3}\",{4:0.00},\"{5}\",\"{6}\"",
                    info.ComputerName,
                    info.SystemType,
                    info.OSVersion,
                    info.CpuInfo,
                    info.TotalMemoryGB,
                    diskInfo.ToString().TrimEnd(';'),
                    networkInfo.ToString().TrimEnd(';')));

                File.WriteAllText(path, csv.ToString(), Encoding.UTF8);
                Console.WriteLine("\n文件已保存到: " + path);
                return Path.GetFullPath(path);
            }
            catch (Exception ex)
            {
                Console.WriteLine("保存文件时出错: " + ex.Message);
                throw;
            }
        }

        static void ShowHelp()
        {
            Console.WriteLine(@"
系统信息收集工具 v3.1 - 使用说明

用法:
  SystemInfoCollector [选项]

选项:
  --protocol <FTP|SMB|TFTP>   指定传输协议 (默认: 不传输)
  --host <地址>               FTP服务器地址
  --ftp-dir <路径>            FTP远程目录
  --smb-server <服务器>       SMB服务器地址
  --smb-share <共享名>        SMB共享名称 (默认: C$)
  --tftp-server <服务器>      TFTP服务器地址 (默认: 192.168.1.100)
  -u, --user <用户名>         登录用户名
  -p, --pass <密码>           登录密码
  --help                      显示帮助信息

示例:
  上传到FTP: SystemInfoCollector --protocol FTP --host ftp.example.com -u admin -p password
  上传到SMB: SystemInfoCollector --protocol SMB --smb-server fileserver -u domain\user -p password
");
        }
        #endregion

        #region 传输协议实现
        static bool FtpTransfer(string localPath, FtpConfig config)
        {
            try
            {
                var uri = new Uri(string.Format("ftp://{0}{1}/{2}",
                    config.Host,
                    config.RemotePath.TrimEnd('/'),
                    Path.GetFileName(localPath)));

                var request = (FtpWebRequest)WebRequest.Create(uri);
                request.Method = WebRequestMethods.Ftp.UploadFile;
                request.Credentials = new NetworkCredential(config.Username, config.Password);
                request.UseBinary = true;

                using (var fs = File.OpenRead(localPath))
                using (var rs = request.GetRequestStream())
                {
                    fs.CopyTo(rs);
                }
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine("FTP错误: " + ex.Message);
                return false;
            }
        }

        static bool SmbTransfer(string localPath, SmbConfig config)
        {
            try
            {
                var destPath = string.Format(@"\\{0}\{1}\{2}",
                    config.Server,
                    config.ShareName,
                    Path.GetFileName(localPath));

                using (new NetworkConnection(
                    string.Format(@"\\{0}\{1}", config.Server, config.ShareName),
                    new NetworkCredential(config.Username, config.Password)))
                {
                    File.Copy(localPath, destPath, true);
                    return true;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("SMB错误: " + ex.Message);
                return false;
            }
        }

        static bool TftpTransfer(string localPath, TftpConfig config)
        {
            try
            {
                Console.WriteLine("TFTP传输中...");
                var client = new TftpClient(config.Server, 69);
                var transfer = client.Upload(Path.GetFileName(localPath));

                bool isFinished = false;
                ulong totalBytes = (ulong)new FileInfo(localPath).Length;

                transfer.OnProgress += delegate(ITftpTransfer t, TftpTransferProgress progress)
                {
                    Console.CursorLeft = 0;
                    double percent = (double)progress.TransferredBytes / totalBytes;
                    Console.Write("进度: {0:P1} ({1}/{2}字节)", 
                        percent, 
                        progress.TransferredBytes, 
                        totalBytes);
                };

                transfer.OnFinished += delegate(ITftpTransfer t)
                {
                    isFinished = true;
                };

                using (var fs = File.OpenRead(localPath))
                {
                    transfer.Start(fs);
                }

                while (!isFinished)
                {
                    System.Threading.Thread.Sleep(100);
                }
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine("\nTFTP错误: " + ex.Message);
                return false;
            }
        }
        #endregion

        #region 命令行解析
        static void ParseCommandLineArgs(string[] args, TransferConfig config)
        {
            if (args.Length == 0)
            {
                return;
            }

            for (int i = 0; i < args.Length; i++)
            {
                var arg = args[i].ToLower();
                try
                {
                    switch (arg)
                    {
                        case "--help":
                            ShowHelp();
                            Environment.Exit(0);
                            break;
                        case "--protocol":
                            if (i + 1 < args.Length)
                                config.Protocol = (TransferProtocol)Enum.Parse(
                                    typeof(TransferProtocol), args[++i], true);
                            break;
                        case "-h":
                        case "--host":
                            config.Ftp.Host = args[++i];
                            break;
                        case "--ftp-dir":
                            config.Ftp.RemotePath = args[++i];
                            break;
                        case "--smb-server":
                            config.Smb.Server = args[++i];
                            break;
                        case "--smb-share":
                            config.Smb.ShareName = args[++i];
                            break;
                        case "--tftp-server":
                            config.Tftp.Server = args[++i];
                            break;
                        case "-u":
                        case "--user":
                            var user = args[++i];
                            config.Ftp.Username = user;
                            config.Smb.Username = user;
                            break;
                        case "-p":
                        case "--pass":
                            var pass = args[++i];
                            config.Ftp.Password = pass;
                            config.Smb.Password = pass;
                            break;
                        default:
                            Console.WriteLine("警告: 未知参数 '" + arg + "'");
                            ShowHelp();
                            Environment.Exit(1);
                            break;
                    }
                }
                catch (IndexOutOfRangeException)
                {
                    Console.WriteLine("错误: 参数 '" + arg + "' 缺少值");
                    ShowHelp();
                    Environment.Exit(1);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("处理参数 '" + arg + "' 时出错: " + ex.Message);
                    ShowHelp();
                    Environment.Exit(1);
                }
            }
        }
        #endregion
    }

    #region 网络连接辅助类
    class NetworkConnection : IDisposable
    {
        [DllImport("mpr.dll")]
        private static extern int WNetAddConnection2(
            ref NETRESOURCE lpNetResource,
            string lpPassword,
            string lpUsername,
            int dwFlags);

        [DllImport("mpr.dll")]
        private static extern int WNetCancelConnection2(
            string lpName,
            int dwFlags,
            bool fForce);

        private readonly string _networkName;

        public NetworkConnection(string networkPath, NetworkCredential credentials)
        {
            var netResource = new NETRESOURCE
            {
                dwType = 1,
                lpRemoteName = networkPath
            };

            _networkName = networkPath;

            int result = WNetAddConnection2(
                ref netResource,
                credentials.Password,
                credentials.UserName,
                0);

            if (result != 0)
            {
                throw new IOException(string.Format("网络连接失败，错误代码：{0}", result));
            }
        }

        public void Dispose()
        {
            WNetCancelConnection2(_networkName, 0, true);
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct NETRESOURCE
        {
            public int dwScope;
            public int dwType;
            public int dwDisplayType;
            public int dwUsage;
            public string lpLocalName;
            public string lpRemoteName;
            public string lpComment;
            public string lpProvider;
        }
    }
    #endregion
}


/*
 %windir%\Microsoft.NET\Framework64\v4.0.30319\csc.exe ^
/out:SystemInfoCollector.exe ^
/reference:System.Management.dll ^
/reference:Tftp.Net.dll ^
SystemInfoCollector.cs
*/