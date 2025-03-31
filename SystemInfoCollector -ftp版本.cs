//编译命令 %windir%\Microsoft.NET\Framework64\v4.0.30319\csc.exe /out:SystemInfoCollector.exe /reference:System.Management.dll SystemInfoCollector.cs


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

namespace SystemInfoCollector
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("=== 系统信息收集工具 ===");
            Console.WriteLine("正在初始化...\n");

            // 默认FTP配置
            var ftpConfig = new FtpConfig
            {
                Host = "ftp.example.com",
                Username = "username",
                Password = "password",
                RemotePath = "/system_info/"
            };

            // 解析命令行参数
            ParseCommandLineArgs(args, ref ftpConfig);

            // 收集系统信息（带终端输出）
            var systemInfo = CollectSystemInfoWithConsoleOutput();

            // 生成文件名
            var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            var fileName = string.Format("{0}_SystemInfo_{1}.csv", systemInfo.ComputerName, timestamp);
            var localPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, fileName);

            // 保存到CSV
            Console.WriteLine("\n正在保存数据到CSV文件...");
            SaveToCsv(systemInfo, localPath);
            Console.WriteLine("√ 文件已保存到: {0}", localPath);

            // 上传到FTP
            Console.WriteLine("\n正在上传到FTP服务器...");
            if (UploadToFtp(localPath, ftpConfig))
            {
                Console.WriteLine("√ 文件已成功上传到: ftp://{0}{1}", ftpConfig.Host, ftpConfig.RemotePath);
            }
            else
            {
                Console.WriteLine("× 文件上传失败");
            }

            Console.WriteLine("\n操作完成。按任意键退出...");
            Console.ReadKey();
        }

        static SystemInfo CollectSystemInfoWithConsoleOutput()
        {
            Console.WriteLine("--- 正在收集系统信息 ---");

            var info = new SystemInfo();

            // 1. 计算机名称
            info.ComputerName = Environment.MachineName;
            Console.WriteLine("计算机名称: {0}", info.ComputerName);

            // 2. 系统类型
            info.SystemType = Environment.Is64BitOperatingSystem ? "64-bit" : "32-bit";
            Console.WriteLine("系统类型: {0}", info.SystemType);

            // 3. 操作系统版本
            Console.Write("正在获取操作系统信息...");
            info.OSVersion = GetOSVersionInfo();
            Console.WriteLine("\r操作系统版本: {0}", info.OSVersion);

            // 4. IP地址
            Console.Write("正在获取IP地址...");
            info.IPAddress = GetIpAddress();
            Console.WriteLine("\rIP地址: {0}", info.IPAddress);

            // 5. MAC地址
            Console.Write("正在获取MAC地址...");
            info.MacAddress = GetMacAddress();
            Console.WriteLine("\rMAC地址: {0}", info.MacAddress);

            // 6. CPU信息
            Console.Write("正在获取CPU信息...");
            info.CpuInfo = GetCpuInfo();
            Console.WriteLine("\rCPU信息: {0}", info.CpuInfo);

            // 7. 内存信息
            Console.Write("正在获取内存信息...");
            info.TotalMemoryGB = GetTotalMemory();
            Console.WriteLine("\r总内存: {0} GB", info.TotalMemoryGB.ToString("0.00"));

            // 8. 磁盘信息
            Console.WriteLine("正在获取磁盘信息...");
            info.PhysicalDisks = GetPhysicalDiskInfo();
            Console.WriteLine("找到 {0} 个物理磁盘:", info.PhysicalDisks.Count);
            foreach (var disk in info.PhysicalDisks)
            {
                Console.WriteLine("  - {0} ({1}): {2} GB", disk.Model, disk.Type, disk.SizeGB.ToString("0.00"));
            }

            return info;
        }

        static void ParseCommandLineArgs(string[] args, ref FtpConfig config)
        {
            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i].ToLower())
                {
                    case "-h":
                    case "--host":
                        if (i + 1 < args.Length) config.Host = args[++i];
                        break;
                    case "-u":
                    case "--user":
                        if (i + 1 < args.Length) config.Username = args[++i];
                        break;
                    case "-p":
                    case "--pass":
                        if (i + 1 < args.Length) config.Password = args[++i];
                        break;
                    case "-d":
                    case "--dir":
                        if (i + 1 < args.Length) config.RemotePath = args[++i];
                        break;
                }
            }
        }

        static string GetOSVersionInfo()
        {
            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion"))
                {
                    if (key != null)
                    {
                        var productName = key.GetValue("ProductName") != null ? key.GetValue("ProductName").ToString() : "Windows";
                        var displayVersion = key.GetValue("DisplayVersion") != null ? key.GetValue("DisplayVersion").ToString() : "";
                        var releaseId = key.GetValue("ReleaseId") != null ? key.GetValue("ReleaseId").ToString() : "";
                        var buildNumber = key.GetValue("CurrentBuildNumber") != null ? key.GetValue("CurrentBuildNumber").ToString() : "";

                        var versionInfo = new StringBuilder(productName);
                        if (!string.IsNullOrEmpty(displayVersion)) versionInfo.Append(" " + displayVersion);
                        else if (!string.IsNullOrEmpty(releaseId)) versionInfo.Append(" " + releaseId);
                        if (!string.IsNullOrEmpty(buildNumber)) versionInfo.Append(" (Build " + buildNumber + ")");

                        return string.Format("{0} - {1}", versionInfo, Environment.OSVersion.VersionString);
                    }
                }
            }
            catch { }
            return Environment.OSVersion.ToString();
        }

        static string GetIpAddress()
        {
            try
            {
                var host = Dns.GetHostEntry(Dns.GetHostName());
                foreach (var ip in host.AddressList)
                {
                    if (ip.AddressFamily == AddressFamily.InterNetwork)
                    {
                        return ip.ToString();
                    }
                }
            }
            catch { }
            return "N/A";
        }

        static string GetMacAddress()
        {
            try
            {
                var nic = NetworkInterface.GetAllNetworkInterfaces()
                    .FirstOrDefault(n => n.OperationalStatus == OperationalStatus.Up && 
                                       n.NetworkInterfaceType != NetworkInterfaceType.Loopback);
                return nic != null ? nic.GetPhysicalAddress().ToString() : "N/A";
            }
            catch { }
            return "N/A";
        }

        static string GetCpuInfo()
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Processor"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        return obj["Name"] != null ? obj["Name"].ToString().Trim() : "N/A";
                    }
                }
            }
            catch { }
            return "N/A";
        }

        static double GetTotalMemory()
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT TotalPhysicalMemory FROM Win32_ComputerSystem"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        if (obj["TotalPhysicalMemory"] != null)
                        {
                            var totalBytes = Convert.ToUInt64(obj["TotalPhysicalMemory"]);
                            return Math.Round(totalBytes / (1024.0 * 1024 * 1024), 2);
                        }
                    }
                }
            }
            catch { }
            return 0;
        }

        static List<PhysicalDisk> GetPhysicalDiskInfo()
        {
            var disks = new List<PhysicalDisk>();
            try
            {
                using (var searcher = new ManagementObjectSearcher(@"SELECT Model, Size, MediaType FROM Win32_DiskDrive"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        var model = obj["Model"] != null ? obj["Model"].ToString().Trim() : "Unknown";
                        var mediaType = obj["MediaType"] != null ? obj["MediaType"].ToString() : "";
                        var size = obj["Size"] != null ? Convert.ToUInt64(obj["Size"]) : 0UL;

                        disks.Add(new PhysicalDisk
                        {
                            Model = model,
                            Type = GetDiskType(mediaType),
                            SizeGB = Math.Round(size / 1024.0 / 1024 / 1024, 2)
                        });
                    }
                }
            }
            catch { }
            return disks.Where(d => d.SizeGB > 0).ToList();
        }

        static string GetDiskType(string mediaType)
        {
            if (string.IsNullOrEmpty(mediaType)) return "Unknown";
            if (mediaType.Contains("SSD")) return "SSD";
            if (mediaType.Contains("HDD")) return "HDD";
            if (mediaType.Contains("Fixed")) return "Fixed";
            return mediaType;
        }

        static void SaveToCsv(SystemInfo info, string filePath)
        {
            var csv = new StringBuilder();
            csv.AppendLine("ComputerName,SystemType,OSVersion,IPAddress,MACAddress,CPUInfo,TotalMemoryGB,DiskCount,DiskInfo");
            
            var diskInfo = new StringBuilder();
            foreach (var disk in info.PhysicalDisks)
            {
                diskInfo.AppendFormat("[{0} {1} {2}GB]; ", disk.Model, disk.Type, disk.SizeGB.ToString("0.00"));
            }
            
            csv.AppendLine(string.Format("\"{0}\",\"{1}\",\"{2}\",\"{3}\",\"{4}\",\"{5}\",{6},{7},\"{8}\"",
                info.ComputerName,
                info.SystemType,
                info.OSVersion,
                info.IPAddress,
                info.MacAddress,
                info.CpuInfo,
                info.TotalMemoryGB.ToString("0.00"),
                info.PhysicalDisks.Count,
                diskInfo.ToString().TrimEnd(';', ' ')));

            File.WriteAllText(filePath, csv.ToString());
        }

        static bool UploadToFtp(string localPath, FtpConfig config)
        {
            try
            {
                var request = (FtpWebRequest)WebRequest.Create(string.Format("ftp://{0}{1}{2}",
                    config.Host,
                    config.RemotePath.TrimEnd('/'),
                    "/" + Path.GetFileName(localPath)));
                
                request.Method = WebRequestMethods.Ftp.UploadFile;
                request.Credentials = new NetworkCredential(config.Username, config.Password);
                request.UseBinary = true;
                request.UsePassive = true;

                using (var fileStream = File.OpenRead(localPath))
                using (var requestStream = request.GetRequestStream())
                {
                    fileStream.CopyTo(requestStream);
                }
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine("FTP上传错误: " + ex.Message);
                return false;
            }
        }
    }

    class SystemInfo
    {
        public string ComputerName { get; set; }
        public string SystemType { get; set; }
        public string OSVersion { get; set; }
        public string IPAddress { get; set; }
        public string MacAddress { get; set; }
        public string CpuInfo { get; set; }
        public double TotalMemoryGB { get; set; }
        public List<PhysicalDisk> PhysicalDisks { get; set; }
    }

    class PhysicalDisk
    {
        public string Model { get; set; }
        public string Type { get; set; }
        public double SizeGB { get; set; }
    }

    class FtpConfig
    {
        public string Host { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public string RemotePath { get; set; }
    }
}