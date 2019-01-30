using System.Reflection;
using System.Windows.Forms;

namespace DnsServerTrayIcon
{
    public static class ContextMenuNotifyIconExtensions
    {
        public static void ShowContextMenu(this NotifyIcon notifyIcon)
        {
            MethodInfo methodInfo = typeof(NotifyIcon).GetMethod("ShowContextMenu", BindingFlags.Instance | BindingFlags.NonPublic);
            methodInfo.Invoke(notifyIcon, null);
        }
    }
}
