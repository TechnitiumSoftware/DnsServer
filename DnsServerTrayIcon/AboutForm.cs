using DnsServerTrayIcon.Properties;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Reflection;
using System.Windows.Forms;

namespace DnsServerTrayIcon
{
    public partial class AboutForm : Form
    {
        public AboutForm()
        {
            InitializeComponent();
            
            Image image = Image.FromFile("Favicon.ico");
            var bitmap = new Bitmap(image);
            Icon = Icon.FromHandle(bitmap.GetHicon());

            VersionLabel.Text = Resources.ServiceName;
            VersionLabel.Text += "\r\n";
            VersionLabel.Text += GetLegalCopyright();
            VersionLabel.Text += "\r\n";
            VersionLabel.Text += Path.GetFileName(Process.GetCurrentProcess().MainModule.FileName) + "  " + Assembly.GetExecutingAssembly().GetBuildVersion();
        }

        private string GetLegalCopyright()
        {
            var versionInfo = FileVersionInfo.GetVersionInfo(Assembly.GetEntryAssembly().Location);
            return versionInfo.LegalCopyright;
        }
    }
}
