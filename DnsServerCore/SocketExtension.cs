/*
Technitium DNS Server
Copyright (C) 2020  Shreyas Zare (shreyas@technitium.com)

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
using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace DnsServerCore
{
    static class SocketExtension
    {
        public static void CloseWorkAround(this Socket socket)
        {
            //issue: https://github.com/dotnet/runtime/issues/37873

            if (Environment.OSVersion.Platform == PlatformID.Win32NT)
            {
                socket.Dispose();
            }
            else
            {
                IPEndPoint localEP = socket.LocalEndPoint as IPEndPoint;
                EventWaitHandle waitHandle = new AutoResetEvent(false);

                ThreadPool.QueueUserWorkItem(delegate (object state)
                {
                    waitHandle.Set();
                    socket.Dispose();
                    waitHandle.Set();
                });

                waitHandle.WaitOne();
                Thread.Sleep(1000); //wait to ensure the above thread has called socket.Dispose()

                //send empty UDP packet to release thread blocking on Socket.ReceiveMessageFrom() call
                using (Socket s = new Socket(localEP.AddressFamily, SocketType.Dgram, ProtocolType.Udp))
                {
                    if (localEP.Address.Equals(IPAddress.Any))
                        localEP = new IPEndPoint(IPAddress.Loopback, localEP.Port);
                    else if (localEP.Address.Equals(IPAddress.IPv6Any))
                        localEP = new IPEndPoint(IPAddress.IPv6Loopback, localEP.Port);

                    s.SendTo(new byte[] { }, localEP);
                }

                waitHandle.WaitOne();
            }
        }
    }
}
