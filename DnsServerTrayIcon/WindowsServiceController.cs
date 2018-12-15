using System.Linq;
using System.ServiceProcess;

namespace DnsServerTrayIcon
{
    public class WindowsServiceController
    {
        private readonly string _serviceName;

        public WindowsServiceController(string serviceName)
        {
            _serviceName = serviceName;
        }

        public void Restart()
        {
            Stop();
            Start();
        }

        public void Stop()
        {
            try
            {
                using (var service = new ServiceController(_serviceName))
                {
                    service.Stop();
                    service.WaitForStatus(ServiceControllerStatus.Stopped);
                }
            }
            catch
            { }
        }

        public void Start()
        {
            try
            {
                using (var service = new ServiceController(_serviceName))
                {
                    service.Start();
                    service.WaitForStatus(ServiceControllerStatus.Running);
                }
            }
            catch
            { }
        }

        public bool IsRunning => Status == ServiceControllerStatus.Running;

        public bool IsStopped => Status == ServiceControllerStatus.Stopped;

        public ServiceControllerStatus Status
        {
            get
            {
                using (var service = new ServiceController(_serviceName))
                {
                    return service.Status;
                }
            }
        }

        public bool IsInstalled
        {
            get
            {
                return ServiceController.GetServices().Any(s => s.ServiceName == _serviceName);
            }
        }
    }
}
