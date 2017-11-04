using System.ComponentModel;
using System.Configuration.Install;
using System.ServiceProcess;

namespace DnsService
{
    [RunInstaller(true)]
    public partial class ProjectInstaller : Installer
    {
        public ProjectInstaller()
        {
            InitializeComponent();

            serviceInstaller1.AfterInstall += ServiceInstaller1_AfterInstall;
            serviceInstaller1.BeforeUninstall += ServiceInstaller1_BeforeUninstall;
        }

        private void ServiceInstaller1_AfterInstall(object sender, InstallEventArgs e)
        {
            new ServiceController(serviceInstaller1.ServiceName).Start();
        }

        private void ServiceInstaller1_BeforeUninstall(object sender, InstallEventArgs e)
        {
            new ServiceController(serviceInstaller1.ServiceName).Stop();
        }
    }
}
