/*
Technitium DNS Server
Copyright (C) 2025  Shreyas Zare (shreyas@technitium.com)

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

using System;
using System.Collections.Generic;
using System.Net.Sockets;

namespace DnsServerCore.Dns
{
    static class SystemdSocketActivation
    {
        const int SD_LISTEN_FDS_START = 3;

        public static IReadOnlyList<Socket> GetSockets()
        {
            string listenPid = Environment.GetEnvironmentVariable("LISTEN_PID");
            string listenFds = Environment.GetEnvironmentVariable("LISTEN_FDS");

            if (listenPid is null || listenFds is null)
                return [];

            if (!int.TryParse(listenPid, out int pid) || pid != Environment.ProcessId)
                return [];

            if (!int.TryParse(listenFds, out int count) || count <= 0)
                return [];

            //unset variables so child processes don't inherit them
            Environment.SetEnvironmentVariable("LISTEN_PID", null);
            Environment.SetEnvironmentVariable("LISTEN_FDS", null);
            Environment.SetEnvironmentVariable("LISTEN_FDNAMES", null);

            List<Socket> sockets = new List<Socket>(count);

            for (int i = 0; i < count; i++)
            {
                int fd = SD_LISTEN_FDS_START + i;
                SafeSocketHandle handle = new SafeSocketHandle(new IntPtr(fd), ownsHandle: true);
                sockets.Add(new Socket(handle));
            }

            return sockets;
        }
    }
}
