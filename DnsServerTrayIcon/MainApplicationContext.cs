using DnsServerTrayIcon.Properties;
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.Windows.Forms;

namespace DnsServerTrayIcon
{
    public class MainApplicationContext : ApplicationContext
    {
        private readonly WindowsServiceController _service = new WindowsServiceController("DnsService");

        private NotifyIcon TrayIcon;
        private ContextMenuStrip TrayIconContextMenu;
        private ToolStripMenuItem DashboardMenuItem;
        private ToolStripMenuItem ServiceMenuItem;
        private ToolStripMenuItem StartServiceMenuItem;
        private ToolStripMenuItem RestartServiceMenuItem;
        private ToolStripMenuItem StopServiceMenuItem;
        private ToolStripMenuItem AboutMenuItem;
        private ToolStripSeparator DividerMenuItem;
        private ToolStripMenuItem ExitMenuItem;

        public MainApplicationContext()
        {
            Application.ApplicationExit += new EventHandler(OnApplicationExit);
            InitializeComponent();
        }

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
            DashboardMenuItem.Click += new EventHandler(DashboardMenuItem_Click);

            //
            // ServiceMenuItem
            //
            ServiceMenuItem = new ToolStripMenuItem();
            ServiceMenuItem.Name = "ServiceMenuItem";
            ServiceMenuItem.Text = Resources.ServiceMenuItem;
            ServiceMenuItem.MouseHover += new EventHandler(ServiceMenuItem_MouseHover);
            // Prove the user feedback that there is a sub menu.
            ServiceMenuItem.DropDownItems.Add(new ToolStripMenuItem());

            StartServiceMenuItem = new ToolStripMenuItem(Resources.ServiceStartMenuItem);
            StartServiceMenuItem.Click += new EventHandler(StartServiceMenuItem_Click);

            RestartServiceMenuItem = new ToolStripMenuItem(Resources.ServiceRestartMenuItem);
            RestartServiceMenuItem.Click += new EventHandler(RestartServiceMenuItem_Click);

            StopServiceMenuItem = new ToolStripMenuItem(Resources.ServiceStopMenuItem);
            StopServiceMenuItem.Click += new EventHandler(StopServiceMenuItem_Click);

            //
            // AboutMenuItem
            //
            AboutMenuItem = new ToolStripMenuItem();
            AboutMenuItem.Name = "AboutMenuItem";
            AboutMenuItem.Text = Resources.AboutMenuItem;
            AboutMenuItem.Click += new EventHandler(AboutMenuItem_Click);

            //
            // DividerMenuItem
            //
            DividerMenuItem = new ToolStripSeparator();

            //
            // CloseMenuItem
            //
            ExitMenuItem = new ToolStripMenuItem();
            ExitMenuItem.Name = "ExitMenuItem";
            ExitMenuItem.Text = Resources.ExitMenuItem;
            ExitMenuItem.Click += new EventHandler(ExitMenuItem_Click);

            TrayIconContextMenu.ResumeLayout(false);
        }

        private void TrayIcon_MouseUp(object sender, MouseEventArgs e)
        {
            if (e.Button == MouseButtons.Right)
            {
                BuildContextMenu();
                TrayIcon.ShowContextMenu();
            }
        }

        private void BuildContextMenu()
        {
            TrayIconContextMenu.Hide();
            TrayIconContextMenu.Items.Clear();

            TrayIconContextMenu.Items.Add(DashboardMenuItem);

            if (_service.IsInstalled)
                TrayIconContextMenu.Items.Add(ServiceMenuItem);

            TrayIconContextMenu.Items.AddRange(new ToolStripItem[]
            {
                DividerMenuItem,
                AboutMenuItem,
                DividerMenuItem,
                ExitMenuItem
            });
        }

        private void ServiceMenuItem_MouseHover(object sender, EventArgs e)
        {
            ServiceMenuItem.DropDownItems.Clear();
            if (_service.IsRunning)
            {
                ServiceMenuItem.DropDownItems.Add(RestartServiceMenuItem);
                ServiceMenuItem.DropDownItems.Add(StopServiceMenuItem);
            }
            else
            {
                ServiceMenuItem.DropDownItems.Add(StartServiceMenuItem);
            }
            ServiceMenuItem.ShowDropDown();
        }

        private void StartServiceMenuItem_Click(object sender, EventArgs e)
        {
            _service.Start();
        }

        private void RestartServiceMenuItem_Click(object sender, EventArgs e)
        {
            _service.Restart();
        }

        private void StopServiceMenuItem_Click(object sender, EventArgs e)
        {
            _service.Stop();
        }

        private void OnApplicationExit(object sender, EventArgs e)
        {
            try
            {
                // Clean up so that the icon will be removed when the application is closed.
                TrayIcon.Visible = false;
            }
            catch (NullReferenceException)
            {
                // The application is probably closing so safe to ignore.
            }
        }

        private void DashboardMenuItem_Click(object sender, EventArgs e)
        {
            //TODO: Parse the config file to determine the port.
            Process.Start("http://127.0.0.1:5380");
        }

        private void AboutMenuItem_Click(object sender, EventArgs e)
        {
            var aboutForm = new AboutForm();
            aboutForm.ShowDialog();
        }

        private void ExitMenuItem_Click(object sender, EventArgs e)
        {
            DialogResult dialogResult = MessageBox.Show(
                Resources.AreYouSureYouWantToQuit,
                Resources.Quit,
                MessageBoxButtons.YesNo,
                MessageBoxIcon.None,
                MessageBoxDefaultButton.Button2);

            if (dialogResult == DialogResult.Yes)
            {
                Application.Exit();
            }
        }
    }
}
