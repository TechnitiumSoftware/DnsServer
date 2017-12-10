/*
Technitium DNS Server
Copyright (C) 2017  Shreyas Zare (shreyas@technitium.com)

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
using System.IO;
using System.Net;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;

namespace DnsServerCore
{
    public class LogManager : IDisposable
    {
        #region variables

        readonly string _logFolder;

        string _logFile;
        StreamWriter _logOut;
        DateTime _logDate;

        #endregion

        #region constructor

        public LogManager(string logFolder)
        {
            _logFolder = logFolder;

            StartNewLog();
        }

        #endregion

        #region IDisposable Support

        private bool disposedValue = false;

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    lock (this)
                    {
                        Write("Logging stopped.");
                        _logOut.Close();
                    }
                }

                disposedValue = true;
            }
        }

        public void Dispose()
        {
            Dispose(true);
        }

        #endregion

        #region private

        private void StartNewLog()
        {
            lock (this)
            {
                DateTime now = DateTime.UtcNow;

                if ((now.Date > _logDate.Date) && (_logOut != null))
                    _logOut.Close();

                _logFile = Path.Combine(_logFolder, now.ToString("yyyy-MM-dd") + ".log");
                _logOut = new StreamWriter(new FileStream(_logFile, FileMode.Append, FileAccess.Write, FileShare.Read));
                _logDate = now;

                Write("Logging started.");
            }
        }

        #endregion

        #region static

        public static void DownloadLog(HttpListenerResponse response, string logFile, long limit)
        {
            using (FileStream fS = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                response.ContentType = "text/plain";
                response.AddHeader("Content-Disposition", "attachment;filename=" + Path.GetFileName(logFile));

                if (limit > fS.Length)
                    limit = fS.Length;

                OffsetStream oFS = new OffsetStream(fS, 0, limit);

                using (Stream s = response.OutputStream)
                {
                    OffsetStream.StreamCopy(oFS, s, 128 * 1024, true);
                }
            }
        }

        #endregion

        #region public

        public void Write(IPEndPoint ep, Exception ex)
        {
            Write(ep, ex.ToString());
        }

        public void Write(IPEndPoint ep, DnsDatagram request, DnsDatagram response)
        {
            DnsQuestionRecord q = request.Question[0];
            string question;

            if (q == null)
                question = "MISSING QUESTION!";
            else
                question = "QNAME: " + q.Name + "; QTYPE: " + q.Type.ToString() + "; QCLASS: " + q.Class;

            string answer;

            if (response.Answer.Length == 0)
            {
                answer = "[]";
            }
            else
            {
                answer = "[";

                for (int i = 0; i < response.Answer.Length; i++)
                {
                    if (i != 0)
                        answer += ", ";

                    answer += response.Answer[i].RDATA.ToString();
                }

                answer += "]";
            }

            Write(ep, question + "; RCODE: " + response.Header.RCODE.ToString() + "; ANSWER: " + answer);
        }

        public void Write(IPEndPoint ep, string message)
        {
            string ipInfo;

            if (ep == null)
                ipInfo = "";
            else if (NetUtilities.IsIPv4MappedIPv6Address(ep.Address))
                ipInfo = "[" + NetUtilities.ConvertFromIPv4MappedIPv6Address(ep.Address).ToString() + ":" + ep.Port + "] ";
            else
                ipInfo = "[" + ep.ToString() + "] ";

            Write(ipInfo + message);
        }

        public void Write(string message)
        {
            DateTime now = DateTime.UtcNow;

            try
            {
                lock (this)
                {
                    if (now.Date > _logDate.Date)
                        StartNewLog();

                    _logOut.WriteLine("[" + now.ToString("yyyy-MM-dd HH:mm:ss") + " UTC] " + message);
                    _logOut.Flush();
                }
            }
            catch
            { }
        }

        public void DeleteCurrentLogFile()
        {
            lock (this)
            {
                _logOut.Close();
                File.Delete(_logFile);

                StartNewLog();
            }
        }

        #endregion

        #region properties

        public string LogFolder
        { get { return _logFolder; } }

        public string CurrentLogFile
        { get { return _logFile; } }

        #endregion
    }
}
