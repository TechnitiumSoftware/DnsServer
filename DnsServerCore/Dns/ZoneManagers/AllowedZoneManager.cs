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

using DnsServerCore.Dns.ResourceRecords;
using DnsServerCore.Dns.Zones;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns.ZoneManagers
{
    public sealed class AllowedZoneManager : IDisposable
    {
        #region variables

        readonly DnsServer _dnsServer;

        AuthZoneManager _zoneManager;

        readonly DnsSOARecordDataExtended _soaRecord;
        readonly DnsNSRecordDataExtended _nsRecord;

        readonly object _saveLock = new object();
        bool _pendingSave;
        readonly Timer _saveTimer;
        const int SAVE_TIMER_INITIAL_INTERVAL = 5000;

        #endregion

        #region constructor

        public AllowedZoneManager(DnsServer dnsServer)
        {
            _dnsServer = dnsServer;

            _zoneManager = new AuthZoneManager(_dnsServer);

            _soaRecord = new DnsSOARecordDataExtended(_dnsServer.ServerDomain, _dnsServer.ResponsiblePerson.Address, 1, 900, 300, 604800, 60);
            _nsRecord = new DnsNSRecordDataExtended(_dnsServer.ServerDomain);

            _saveTimer = new Timer(delegate (object state)
            {
                lock (_saveLock)
                {
                    if (_pendingSave)
                    {
                        try
                        {
                            SaveZoneFileInternal();
                            _pendingSave = false;
                        }
                        catch (Exception ex)
                        {
                            _dnsServer.LogManager.Write(ex);

                            //set timer to retry again
                            _saveTimer.Change(SAVE_TIMER_INITIAL_INTERVAL, Timeout.Infinite);
                        }
                    }
                }
            });
        }

        #endregion

        #region IDisposable

        bool _disposed;

        public void Dispose()
        {
            if (_disposed)
                return;

            lock (_saveLock)
            {
                _saveTimer?.Dispose();

                if (_pendingSave)
                {
                    try
                    {
                        SaveZoneFileInternal();
                    }
                    catch (Exception ex)
                    {
                        _dnsServer.LogManager.Write(ex);
                    }
                    finally
                    {
                        _pendingSave = false;
                    }
                }
            }

            _disposed = true;
        }

        #endregion

        #region zone file

        public void LoadAllowedZoneFile()
        {
            string allowedZoneFile = Path.Combine(_dnsServer.ConfigFolder, "allowed.config");

            try
            {
                using (FileStream fS = new FileStream(allowedZoneFile, FileMode.Open, FileAccess.Read))
                {
                    ReadConfigFrom(fS);
                }

                _dnsServer.LogManager.Write("DNS Server allowed zone file was loaded: " + allowedZoneFile);
            }
            catch (FileNotFoundException)
            {
                SaveZoneFileInternal();
            }
            catch (Exception ex)
            {
                _dnsServer.LogManager.Write("DNS Server encountered an error while loading allowed zone file: " + allowedZoneFile + "\r\n" + ex.ToString());
            }
        }

        public void LoadAllowedZone(Stream s)
        {
            lock (_saveLock)
            {
                ReadConfigFrom(s);

                SaveZoneFileInternal();

                if (_pendingSave)
                {
                    _pendingSave = false;
                    _saveTimer.Change(Timeout.Infinite, Timeout.Infinite);
                }
            }
        }

        private void SaveZoneFileInternal()
        {
            string allowedZoneFile = Path.Combine(_dnsServer.ConfigFolder, "allowed.config");

            using (FileStream fS = new FileStream(allowedZoneFile, FileMode.Create, FileAccess.Write))
            {
                WriteConfigTo(fS);
            }

            _dnsServer.LogManager.Write("DNS Server allowed zone file was saved: " + allowedZoneFile);
        }

        public void SaveZoneFile()
        {
            lock (_saveLock)
            {
                if (_pendingSave)
                    return;

                _pendingSave = true;
                _saveTimer.Change(SAVE_TIMER_INITIAL_INTERVAL, Timeout.Infinite);
            }
        }

        private void ReadConfigFrom(Stream s)
        {
            BinaryReader bR = new BinaryReader(s);

            if (Encoding.ASCII.GetString(bR.ReadBytes(2)) != "AZ") //format
                throw new InvalidDataException("DnsServer allowed zone file format is invalid.");

            byte version = bR.ReadByte();
            switch (version)
            {
                case 1:
                    int length = bR.ReadInt32();
                    int i = 0;

                    AuthZoneManager zoneManager = new AuthZoneManager(_dnsServer);

                    zoneManager.LoadSpecialPrimaryZones(delegate ()
                    {
                        if (i++ < length)
                            return bR.ReadShortString();

                        return null;
                    }, _soaRecord, _nsRecord);

                    _zoneManager = zoneManager;
                    break;

                default:
                    throw new InvalidDataException("DnsServer allowed zone file version not supported.");
            }
        }

        private void WriteConfigTo(Stream s)
        {
            IReadOnlyList<AuthZoneInfo> allowedZones = _zoneManager.GetAllZones();
            BinaryWriter bW = new BinaryWriter(s);

            bW.Write(Encoding.ASCII.GetBytes("AZ")); //format
            bW.Write((byte)1); //version

            bW.Write(allowedZones.Count);

            foreach (AuthZoneInfo zone in allowedZones)
                bW.WriteShortString(zone.Name);
        }

        #endregion

        #region private

        internal void UpdateServerDomain()
        {
            _soaRecord.UpdatePrimaryNameServerAndMinimum(_dnsServer.ServerDomain, _dnsServer.BlockingAnswerTtl);
            _nsRecord.UpdateNameServer(_dnsServer.ServerDomain);
        }

        #endregion

        #region public

        public void ImportZones(string[] domains)
        {
            _zoneManager.LoadSpecialPrimaryZones(domains, _soaRecord, _nsRecord);
        }

        public bool AllowZone(string domain)
        {
            if (_zoneManager.CreateSpecialPrimaryZone(domain, _soaRecord, _nsRecord) != null)
                return true;

            return false;
        }

        public bool DeleteZone(string domain)
        {
            if (_zoneManager.DeleteZone(domain))
                return true;

            return false;
        }

        public void Flush()
        {
            _zoneManager.Flush();
        }

        public IReadOnlyList<AuthZoneInfo> GetAllZones()
        {
            return _zoneManager.GetAllZones();
        }

        public void ListAllRecords(string domain, List<DnsResourceRecord> records)
        {
            _zoneManager.ListAllRecords(domain, domain, records);
        }

        public void ListSubDomains(string domain, List<string> subDomains)
        {
            _zoneManager.ListSubDomains(domain, subDomains);
        }

        public bool IsAllowed(DnsDatagram request)
        {
            if (_zoneManager.TotalZones < 1)
                return false;

            return _zoneManager.Query(request, false) is not null;
        }

        #endregion

        #region properties

        public int TotalZonesAllowed
        { get { return _zoneManager.TotalZones; } }

        #endregion
    }
}
