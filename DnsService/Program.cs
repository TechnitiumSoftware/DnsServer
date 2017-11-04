using System.ServiceProcess;

namespace DnsService
{
    static class Program
    {
        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        static void Main()
        {
            ServiceBase[] ServicesToRun;
            ServicesToRun = new ServiceBase[]
            {
                new DnsService()
            };
            ServiceBase.Run(ServicesToRun);
        }
    }
}
