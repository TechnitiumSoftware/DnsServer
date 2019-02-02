/*
Technitium DNS Server
Copyright (C) 2019  Shreyas Zare (shreyas@technitium.com)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

using DnsServerSystemTrayApp.Properties;
using Microsoft.Win32;
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection;
using System.ServiceProcess;
using System.Text;
using System.Windows.Forms;
using TechnitiumLibrary.IO;

namespace DnsServerSystemTrayApp
{
    public class MainApplicationContext : ApplicationContext
    {
        #region variables

        const int SERVICE_WAIT_TIMEOUT_SECONDS = 30;
        private readonly ServiceController _service = new ServiceController("DnsService");

        readonly IPAddress[] _cloudflareDns = new IPAddress[] { IPAddress.Parse("1.1.1.1"), IPAddress.Parse("1.0.0.1") };
        readonly IPAddress[] _googleDns = new IPAddress[] { IPAddress.Parse("8.8.8.8"), IPAddress.Parse("8.8.4.4") };
        readonly IPAddress[] _quad9Dns = new IPAddress[] { IPAddress.Parse("9.9.9.9") };

        private NotifyIcon TrayIcon;
        private ContextMenuStrip TrayIconContextMenu;
        private ToolStripMenuItem DashboardMenuItem;
        private ToolStripMenuItem NetworkDnsMenuItem;
        private ToolStripMenuItem DefaultNetworkDnsMenuItem;
        private ToolStripMenuItem TechnitiumNetworkDnsMenuItem;
        private ToolStripMenuItem CloudflareNetworkDnsMenuItem;
        private ToolStripMenuItem GoogleNetworkDnsMenuItem;
        private ToolStripMenuItem Quad9NetworkDnsMenuItem;
        private ToolStripMenuItem ServiceMenuItem;
        private ToolStripMenuItem StartServiceMenuItem;
        private ToolStripMenuItem RestartServiceMenuItem;
        private ToolStripMenuItem StopServiceMenuItem;
        private ToolStripMenuItem AboutMenuItem;
        private ToolStripMenuItem AutoStartMenuItem;
        private ToolStripMenuItem ExitMenuItem;

        #endregion

        #region constructor

        public MainApplicationContext()
        {
            InitializeComponent();
        }

        #endregion

        #region IDisposable

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                TrayIcon?.Dispose();
            }

            base.Dispose(disposing);
        }

        #endregion

        #region private

        private void InitializeComponent()
        {
            //
            // TrayIconContextMenu
            //
            TrayIconContextMenu = new ContextMenuStrip();
            TrayIconContextMenu.SuspendLayout();

            //
            // TrayIcon
            //
            var resources = new ComponentResourceManager(typeof(AboutForm));
            TrayIcon = new NotifyIcon();
            TrayIcon.Icon = (Icon)resources.GetObject("$this.Icon");
            TrayIcon.Visible = true;
            TrayIcon.MouseUp += TrayIcon_MouseUp;
            TrayIcon.ContextMenuStrip = TrayIconContextMenu;
            TrayIcon.Text = Resources.ServiceName;

            //
            // DashboardMenuItem
            //
            DashboardMenuItem = new ToolStripMenuItem();
            DashboardMenuItem.Name = "DashboardMenuItem";
            DashboardMenuItem.Text = Resources.DashboardMenuItem;
            DashboardMenuItem.Click += DashboardMenuItem_Click;


            //
            // NetworkDnsMenuItem
            //
            NetworkDnsMenuItem = new ToolStripMenuItem();
            NetworkDnsMenuItem.Name = "NetworkDnsMenuItem";
            NetworkDnsMenuItem.Text = Resources.NetworkDnsMenuItem;

            DefaultNetworkDnsMenuItem = new ToolStripMenuItem("Default");
            DefaultNetworkDnsMenuItem.Click += DefaultNetworkDnsMenuItem_Click;

            TechnitiumNetworkDnsMenuItem = new ToolStripMenuItem("Technitium");
            TechnitiumNetworkDnsMenuItem.Click += TechnitiumNetworkDnsMenuItem_Click;

            CloudflareNetworkDnsMenuItem = new ToolStripMenuItem("Cloudflare");
            CloudflareNetworkDnsMenuItem.Click += CloudflareNetworkDnsMenuItem_Click;

            GoogleNetworkDnsMenuItem = new ToolStripMenuItem("Google");
            GoogleNetworkDnsMenuItem.Click += GoogleNetworkDnsMenuItem_Click;

            Quad9NetworkDnsMenuItem = new ToolStripMenuItem("IBM Quad9");
            Quad9NetworkDnsMenuItem.Click += Quad9NetworkDnsMenuItem_Click;

            NetworkDnsMenuItem.DropDownItems.AddRange(new ToolStripItem[]
            {
                DefaultNetworkDnsMenuItem,
                new ToolStripSeparator(),
                TechnitiumNetworkDnsMenuItem,
                CloudflareNetworkDnsMenuItem,
                GoogleNetworkDnsMenuItem,
                Quad9NetworkDnsMenuItem
            });

            //
            // ServiceMenuItem
            //
            ServiceMenuItem = new ToolStripMenuItem();
            ServiceMenuItem.Name = "ServiceMenuItem";
            ServiceMenuItem.Text = Resources.ServiceMenuItem;

            StartServiceMenuItem = new ToolStripMenuItem(Resources.ServiceStartMenuItem);
            StartServiceMenuItem.Click += StartServiceMenuItem_Click;

            RestartServiceMenuItem = new ToolStripMenuItem(Resources.ServiceRestartMenuItem);
            RestartServiceMenuItem.Click += RestartServiceMenuItem_Click;

            StopServiceMenuItem = new ToolStripMenuItem(Resources.ServiceStopMenuItem);
            StopServiceMenuItem.Click += StopServiceMenuItem_Click;

            ServiceMenuItem.DropDownItems.AddRange(new ToolStripItem[]
            {
                StartServiceMenuItem,
                RestartServiceMenuItem,
                StopServiceMenuItem
            });

            //
            // AboutMenuItem
            //
            AboutMenuItem = new ToolStripMenuItem();
            AboutMenuItem.Name = "AboutMenuItem";
            AboutMenuItem.Text = Resources.AboutMenuItem;
            AboutMenuItem.Click += AboutMenuItem_Click;

            //
            // AutoStartMenuItem
            //
            AutoStartMenuItem = new ToolStripMenuItem();
            AutoStartMenuItem.Name = "AutoStartMenuItem";
            AutoStartMenuItem.Text = "&Auto Start Icon";
            AutoStartMenuItem.Click += AutoStartMenuItem_Click;

            //
            // ExitMenuItem
            //
            ExitMenuItem = new ToolStripMenuItem();
            ExitMenuItem.Name = "ExitMenuItem";
            ExitMenuItem.Text = Resources.ExitMenuItem;
            ExitMenuItem.Click += ExitMenuItem_Click;

            TrayIconContextMenu.Items.AddRange(new ToolStripItem[]
            {
                DashboardMenuItem,
                new ToolStripSeparator(),
                NetworkDnsMenuItem,
                ServiceMenuItem,
                AboutMenuItem,
                new ToolStripSeparator(),
                AutoStartMenuItem,
                ExitMenuItem
            });

            TrayIconContextMenu.ResumeLayout(false);
        }

        private static void SetNameServerIPv4(NetworkInterface nic, IPAddress[] dnsAddresses)
        {
            ManagementClass networkAdapterConfig = new ManagementClass("Win32_NetworkAdapterConfiguration");
            ManagementObjectCollection instances = networkAdapterConfig.GetInstances();

            foreach (ManagementObject obj in instances)
            {
                if ((bool)obj["IPEnabled"] && obj["SettingID"].Equals(nic.Id))
                {
                    string[] dnsServers = new string[dnsAddresses.Length];

                    for (int i = 0; i < dnsServers.Length; i++)
                    {
                        if (dnsAddresses[i].AddressFamily != AddressFamily.InterNetwork)
                            throw new ArgumentException();

                        dnsServers[i] = dnsAddresses[i].ToString();
                    }
                    ManagementBaseObject objParameter = obj.GetMethodParameters("SetDNSServerSearchOrder");
                    objParameter["DNSServerSearchOrder"] = dnsServers;

                    ManagementBaseObject response = obj.InvokeMethod("SetDNSServerSearchOrder", objParameter, null);
                    uint returnValue = (uint)response.GetPropertyValue("ReturnValue");

                    switch (returnValue)
                    {
                        case 0: //success
                        case 1: //reboot required
                            break;

                        case 64:
                            throw new Exception("Method not supported on this platform. WMI error code: " + returnValue);

                        case 65:
                            throw new Exception("Unknown failure. WMI error code: " + returnValue);

                        case 70:
                            throw new Exception("Invalid IP address. WMI error code: " + returnValue);

                        case 96:
                            throw new Exception("Unable to notify DNS service. WMI error code: " + returnValue);

                        case 97:
                            throw new Exception("Interface not configurable. WMI error code: " + returnValue);

                        default:
                            throw new Exception("WMI error code: " + returnValue);
                    }

                    break;
                }
            }
        }

        private static void SetNameServerIPv6(NetworkInterface nic, IPAddress[] dnsAddresses)
        {
            //HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\{}

            string nameServer = null;

            foreach (IPAddress dnsAddress in dnsAddresses)
            {
                if (dnsAddress.AddressFamily != AddressFamily.InterNetworkV6)
                    throw new ArgumentException();

                if (nameServer == null)
                    nameServer = dnsAddress.ToString();
                else
                    nameServer += "," + dnsAddress.ToString();
            }

            if (nameServer == null)
                nameServer = "";

            using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\" + nic.Id, true))
            {
                if (key != null)
                    key.SetValue("NameServer", nameServer, RegistryValueKind.String);
            }
        }

        private static bool AddressExists(IPAddress checkAddress, IPAddress[] addresses)
        {
            foreach (IPAddress address in addresses)
            {
                if (checkAddress.Equals(address))
                    return true;
            }

            return false;
        }

        private void TrayIcon_MouseUp(object sender, MouseEventArgs e)
        {
            if (e.Button == MouseButtons.Right)
            {
                #region Network DNS

                bool isDefaultDns = false;
                bool isTechnitiumDns = false;
                bool isCloudflareDns = false;
                bool isGoogleDns = false;
                bool isQuad9Dns = false;

                try
                {
                    foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
                    {
                        if (nic.OperationalStatus != OperationalStatus.Up)
                            continue;

                        foreach (IPAddress dnsAddress in nic.GetIPProperties().DnsAddresses)
                        {
                            if (IPAddress.IsLoopback(dnsAddress))
                            {
                                isTechnitiumDns = true;
                            }
                            else if (AddressExists(dnsAddress, _cloudflareDns))
                            {
                                isCloudflareDns = true;
                            }
                            else if (AddressExists(dnsAddress, _googleDns))
                            {
                                isGoogleDns = true;
                            }
                            else if (AddressExists(dnsAddress, _quad9Dns))
                            {
                                isQuad9Dns = true;
                            }
                            else if (!dnsAddress.IsIPv6SiteLocal)
                            {
                                isDefaultDns = true;
                            }

                            if (isDefaultDns && isTechnitiumDns && isCloudflareDns && isGoogleDns && isQuad9Dns)
                                break;
                        }
                    }
                }
                catch
                { }

                DefaultNetworkDnsMenuItem.Checked = isDefaultDns;
                TechnitiumNetworkDnsMenuItem.Checked = isTechnitiumDns;
                CloudflareNetworkDnsMenuItem.Checked = isCloudflareDns;
                GoogleNetworkDnsMenuItem.Checked = isGoogleDns;
                Quad9NetworkDnsMenuItem.Checked = isQuad9Dns;

                #endregion

                #region service

                try
                {
                    switch (_service.Status)
                    {
                        case ServiceControllerStatus.Stopped:
                            TechnitiumNetworkDnsMenuItem.Enabled = false;
                            DashboardMenuItem.Enabled = false;
                            StartServiceMenuItem.Enabled = true;
                            RestartServiceMenuItem.Enabled = false;
                            StopServiceMenuItem.Enabled = false;
                            break;

                        case ServiceControllerStatus.Running:
                            TechnitiumNetworkDnsMenuItem.Enabled = true;
                            DashboardMenuItem.Enabled = true;
                            StartServiceMenuItem.Enabled = false;
                            RestartServiceMenuItem.Enabled = true;
                            StopServiceMenuItem.Enabled = true;
                            break;

                        default:
                            TechnitiumNetworkDnsMenuItem.Enabled = false;
                            DashboardMenuItem.Enabled = false;
                            StartServiceMenuItem.Enabled = false;
                            RestartServiceMenuItem.Enabled = false;
                            StopServiceMenuItem.Enabled = false;
                            break;
                    }

                    ServiceMenuItem.Enabled = true;
                }
                catch
                {
                    TechnitiumNetworkDnsMenuItem.Enabled = false;
                    DashboardMenuItem.Enabled = false;
                    ServiceMenuItem.Enabled = false;
                }

                #endregion

                #region auto start

                try
                {
                    using (RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", true))
                    {
                        if (key != null)
                        {
                            string autoStartPath = key.GetValue("Technitium DNS System Tray") as string;

                            AutoStartMenuItem.Checked = (autoStartPath != null) && autoStartPath.Equals("\"" + Assembly.GetEntryAssembly().Location + "\"");
                        }
                    }
                }
                catch
                { }

                #endregion

                TrayIcon.ShowContextMenu();
            }
        }

        private void DashboardMenuItem_Click(object sender, EventArgs e)
        {
            int port = 5380;

            try
            {
                //try finding port number from dns config file

                string dnsConfigFile = Path.Combine(Path.GetDirectoryName(Assembly.GetEntryAssembly().Location), "config", "dns.config");

                using (FileStream fS = new FileStream(dnsConfigFile, FileMode.Open, FileAccess.Read))
                {
                    BinaryReader bR = new BinaryReader(fS);

                    if (Encoding.ASCII.GetString(bR.ReadBytes(2)) != "DS") //format
                        throw new InvalidDataException("DnsServer config file format is invalid.");

                    int version = bR.ReadByte();

                    if (version > 1)
                    {
                        string serverDomain = bR.ReadShortString();
                        port = bR.ReadInt32();
                    }
                }
            }
            catch
            { }

            Process.Start("http://localhost:" + port.ToString());
        }

        private void DefaultNetworkDnsMenuItem_Click(object sender, EventArgs e)
        {
            try
            {
                foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (nic.OperationalStatus != OperationalStatus.Up)
                        continue;

                    SetNameServerIPv6(nic, new IPAddress[] { });

                    IPInterfaceProperties properties = nic.GetIPProperties();

                    if (properties.GetIPv4Properties().IsDhcpEnabled)
                    {
                        SetNameServerIPv4(nic, new IPAddress[] { });
                    }
                    else if (properties.GatewayAddresses.Count > 0)
                    {
                        SetNameServerIPv4(nic, new IPAddress[] { properties.GatewayAddresses[0].Address });
                    }
                    else
                    {
                        SetNameServerIPv4(nic, new IPAddress[] { });
                    }
                }

                MessageBox.Show("The network DNS servers were set to default successfully.", "Default DNS Set - " + Resources.ServiceName, MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error occured while setting default network DNS servers. " + ex.Message, "Error - " + Resources.ServiceName, MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void TechnitiumNetworkDnsMenuItem_Click(object sender, EventArgs e)
        {
            try
            {
                foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (nic.OperationalStatus != OperationalStatus.Up)
                        continue;

                    IPInterfaceProperties properties = nic.GetIPProperties();

                    if ((properties.DnsAddresses.Count > 0) && !properties.DnsAddresses[0].IsIPv6SiteLocal)
                    {
                        SetNameServerIPv6(nic, new IPAddress[] { IPAddress.IPv6Loopback });
                        SetNameServerIPv4(nic, new IPAddress[] { IPAddress.Loopback });
                    }
                }

                MessageBox.Show("The network DNS servers were set to Technitium DNS successfully.", "Technitium DNS Set - " + Resources.ServiceName, MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error occured while setting Technitium as network DNS server. " + ex.Message, "Error - " + Resources.ServiceName, MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void CloudflareNetworkDnsMenuItem_Click(object sender, EventArgs e)
        {
            try
            {
                foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (nic.OperationalStatus != OperationalStatus.Up)
                        continue;

                    IPInterfaceProperties properties = nic.GetIPProperties();

                    if ((properties.DnsAddresses.Count > 0) && !properties.DnsAddresses[0].IsIPv6SiteLocal)
                    {
                        SetNameServerIPv6(nic, new IPAddress[] { });
                        SetNameServerIPv4(nic, _cloudflareDns);
                    }
                }

                MessageBox.Show("The network DNS servers were set to Cloudflare DNS successfully.", "Cloudflare DNS Set - " + Resources.ServiceName, MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error occured while setting Cloudflare as network DNS server. " + ex.Message, "Error - " + Resources.ServiceName, MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void GoogleNetworkDnsMenuItem_Click(object sender, EventArgs e)
        {
            try
            {
                foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (nic.OperationalStatus != OperationalStatus.Up)
                        continue;

                    IPInterfaceProperties properties = nic.GetIPProperties();

                    if ((properties.DnsAddresses.Count > 0) && !properties.DnsAddresses[0].IsIPv6SiteLocal)
                    {
                        SetNameServerIPv6(nic, new IPAddress[] { });
                        SetNameServerIPv4(nic, _googleDns);
                    }
                }

                MessageBox.Show("The network DNS servers were set to Google DNS successfully.", "Google DNS Set - " + Resources.ServiceName, MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error occured while setting Google as network DNS server. " + ex.Message, "Error - " + Resources.ServiceName, MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void Quad9NetworkDnsMenuItem_Click(object sender, EventArgs e)
        {
            try
            {
                foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (nic.OperationalStatus != OperationalStatus.Up)
                        continue;

                    IPInterfaceProperties properties = nic.GetIPProperties();

                    if ((properties.DnsAddresses.Count > 0) && !properties.DnsAddresses[0].IsIPv6SiteLocal)
                    {
                        SetNameServerIPv6(nic, new IPAddress[] { });
                        SetNameServerIPv4(nic, _quad9Dns);
                    }
                }

                MessageBox.Show("The network DNS servers were set to IBM Quad9 DNS successfully.", "IBM Quad9 DNS Set - " + Resources.ServiceName, MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error occured while setting IBM Quad9 as network DNS server. " + ex.Message, "Error - " + Resources.ServiceName, MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void StartServiceMenuItem_Click(object sender, EventArgs e)
        {
            try
            {
                _service.Start();
                _service.WaitForStatus(ServiceControllerStatus.Running, new TimeSpan(0, 0, SERVICE_WAIT_TIMEOUT_SECONDS));

                MessageBox.Show("The service was started successfully.", "Service Started - " + Resources.ServiceName, MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (System.ServiceProcess.TimeoutException ex)
            {
                MessageBox.Show("The service did not respond in time." + ex.Message, "Service Error - " + Resources.ServiceName, MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error occured while starting service. " + ex.Message, "Service Error - " + Resources.ServiceName, MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void RestartServiceMenuItem_Click(object sender, EventArgs e)
        {
            try
            {
                _service.Stop();
                _service.WaitForStatus(ServiceControllerStatus.Stopped, new TimeSpan(0, 0, SERVICE_WAIT_TIMEOUT_SECONDS));
                _service.Start();
                _service.WaitForStatus(ServiceControllerStatus.Running, new TimeSpan(0, 0, SERVICE_WAIT_TIMEOUT_SECONDS));

                MessageBox.Show("The service was restarted successfully.", "Service Restarted - " + Resources.ServiceName, MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (System.ServiceProcess.TimeoutException ex)
            {
                MessageBox.Show("The service did not respond in time." + ex.Message, "Service Error - " + Resources.ServiceName, MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error occured while restarting service. " + ex.Message, "Service Error - " + Resources.ServiceName, MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void StopServiceMenuItem_Click(object sender, EventArgs e)
        {
            try
            {
                _service.Stop();
                _service.WaitForStatus(ServiceControllerStatus.Stopped, new TimeSpan(0, 0, SERVICE_WAIT_TIMEOUT_SECONDS));

                MessageBox.Show("The service was stopped successfully.", "Service Stopped - " + Resources.ServiceName, MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (System.ServiceProcess.TimeoutException ex)
            {
                MessageBox.Show("The service did not respond in time." + ex.Message, "Service Error - " + Resources.ServiceName, MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error occured while stopping service. " + ex.Message, "Service Error - " + Resources.ServiceName, MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void AboutMenuItem_Click(object sender, EventArgs e)
        {
            using (AboutForm aboutForm = new AboutForm())
            {
                aboutForm.ShowDialog();
            }
        }

        private void AutoStartMenuItem_Click(object sender, EventArgs e)
        {
            if (AutoStartMenuItem.Checked)
            {
                //remove
                try
                {
                    using (RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", true))
                    {
                        if (key != null)
                            key.DeleteValue("Technitium DNS System Tray", false);
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Error occured while removing auto start registry entry. " + ex.Message, "Error - " + Resources.ServiceName, MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
            else
            {
                //add
                try
                {
                    using (RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", true))
                    {
                        if (key != null)
                            key.SetValue("Technitium DNS System Tray", "\"" + Assembly.GetEntryAssembly().Location + "\"", RegistryValueKind.String);
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Error occured while adding auto start registry entry. " + ex.Message, "Error - " + Resources.ServiceName, MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }

        private void ExitMenuItem_Click(object sender, EventArgs e)
        {
            if (MessageBox.Show(Resources.AreYouSureYouWantToQuit, Resources.Quit + " - " + Resources.ServiceName, MessageBoxButtons.YesNo, MessageBoxIcon.Question, MessageBoxDefaultButton.Button2) == DialogResult.Yes)
                Application.Exit();
        }

        #endregion
    }
}
