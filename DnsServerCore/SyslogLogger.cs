/*
Technitium DNS Server
Copyright (C) 2026  Shreyas Zare (shreyas@technitium.com)

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
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace DnsServerCore
{
    public enum SyslogSeverity : byte
    {
        Emergency = 0,
        Alert = 1,
        Critical = 2,
        Error = 3,
        Warning = 4,
        Notice = 5,
        Informational = 6,
        Debug = 7
    }

    public sealed class SyslogLogger : IDisposable
    {
        #region variables

        public const int DEFAULT_PORT = 514;
        public const int MAX_MESSAGE_SIZE = 2048; //RFC 5424 section 6.1

        const byte FACILITY = 16; //local0

        const string APP_NAME = "TechnitiumDnsServer";

        static readonly string _hostName = SanitizeHostName(System.Net.Dns.GetHostName());
        static readonly string _procId = Environment.ProcessId.ToString(CultureInfo.InvariantCulture);

        readonly object _lock = new object();
        UdpClient _udpClient;
        IPEndPoint _remoteEndPoint;

        bool _enabled;
        IPAddress _serverAddress;
        int _serverPort;

        #endregion

        #region constructor

        public SyslogLogger()
        {
            _serverPort = DEFAULT_PORT;
        }

        #endregion

        #region IDisposable

        bool _disposed;

        public void Dispose()
        {
            if (_disposed)
                return;

            lock (_lock)
            {
                CloseUdpClient();
                _enabled = false;
            }

            _disposed = true;
        }

        #endregion

        #region public

        public bool IsEnabled
        { get { return _enabled; } }

        public void Update(IPAddress serverAddress, int serverPort)
        {
            lock (_lock)
            {
                CloseUdpClient();

                if ((serverAddress is null) || (serverPort < 1) || (serverPort > 65535))
                {
                    //disable syslog
                    _enabled = false;
                    _serverAddress = null;
                    _serverPort = DEFAULT_PORT;
                    return;
                }

                _serverAddress = serverAddress;
                _serverPort = serverPort;
                _remoteEndPoint = new IPEndPoint(serverAddress, serverPort);
                _enabled = true;
            }
        }

        public void Send(string message, SyslogSeverity severity, DateTime timestampUtc)
        {
            byte[] datagram = BuildMessage(message, severity, timestampUtc);

            lock (_lock)
            {
                if (!_enabled || (_remoteEndPoint is null))
                    return;

                try
                {
                    if (_udpClient is null)
                        _udpClient = new UdpClient();

                    _udpClient.Send(datagram, datagram.Length, _remoteEndPoint);
                }
                catch (Exception)
                {
                    //recreate the client on the next send so that a transient failure self-heals
                    CloseUdpClient();
                }
            }
        }

        #endregion

        #region private

        private static string SanitizeHostName(string hostName)
        {
            //RFC 5424: HOSTNAME must contain only printable US-ASCII characters (33-126)
            if (string.IsNullOrEmpty(hostName))
                return "-";

            StringBuilder sanitized = new StringBuilder(hostName.Length);

            foreach (char c in hostName)
            {
                if ((c >= 33) && (c <= 126))
                    sanitized.Append(c);
            }

            return (sanitized.Length > 0) ? sanitized.ToString() : "-";
        }

        private static byte[] BuildMessage(string message, SyslogSeverity severity, DateTime timestampUtc)
        {
            int pri = (FACILITY * 8) + (int)severity;

            string header = "<" + pri.ToString(CultureInfo.InvariantCulture) + ">1 "
                + timestampUtc.ToString("yyyy-MM-ddTHH:mm:ss.ffffffZ", CultureInfo.InvariantCulture)
                + " " + _hostName
                + " " + APP_NAME
                + " " + _procId
                + " - - "; //msgid; NIL structured-data

            byte[] headerBytes = Encoding.ASCII.GetBytes(header);
            byte[] msgBytes = new byte[3 + Encoding.UTF8.GetByteCount(message)]; //UTF-8 BOM + MSG
            msgBytes[0] = 0xEF;
            msgBytes[1] = 0xBB;
            msgBytes[2] = 0xBF;
            Encoding.UTF8.GetBytes(message, 0, message.Length, msgBytes, 3);

            if (headerBytes.Length + msgBytes.Length <= MAX_MESSAGE_SIZE)
            {
                byte[] datagram = new byte[headerBytes.Length + msgBytes.Length];
                Buffer.BlockCopy(headerBytes, 0, datagram, 0, headerBytes.Length);
                Buffer.BlockCopy(msgBytes, 0, datagram, headerBytes.Length, msgBytes.Length);

                return datagram;
            }

            //truncate on a UTF-8 char boundary within the message part
            int maxMsgBytes = MAX_MESSAGE_SIZE - headerBytes.Length;

            for (int count = Math.Min(maxMsgBytes, msgBytes.Length); count > 0; count--)
            {
                if ((msgBytes[count] & 0xC0) != 0x80) //not a UTF-8 continuation byte
                {
                    byte[] datagram = new byte[headerBytes.Length + count];
                    Buffer.BlockCopy(headerBytes, 0, datagram, 0, headerBytes.Length);
                    Buffer.BlockCopy(msgBytes, 0, datagram, headerBytes.Length, count);

                    return datagram;
                }
            }

            return headerBytes;
        }

        private void CloseUdpClient()
        {
            if (_udpClient is not null)
            {
                try
                {
                    _udpClient.Dispose();
                }
                catch (Exception)
                {
                    //ignore
                }

                _udpClient = null;
            }
        }

        #endregion
    }
}
