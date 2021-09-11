/*
Technitium DNS Server
Copyright (C) 2021  Shreyas Zare (shreyas@technitium.com)

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

using DnsServerCore.Dns.Zones;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns.ZoneManagers
{
    public sealed class BlockedZoneManager
    {
        #region variables

        readonly DnsServer _dnsServer;

        readonly AuthZoneManager _zoneManager;

        DnsSOARecord _soaRecord;
        DnsNSRecord _nsRecord;

        #endregion

        #region constructor

        public BlockedZoneManager(DnsServer dnsServer)
        {
            _dnsServer = dnsServer;

            _zoneManager = new AuthZoneManager(_dnsServer);

            UpdateServerDomain(_dnsServer.ServerDomain);
        }

        #endregion

        #region private

        private void UpdateServerDomain(string serverDomain)
        {
            _soaRecord = new DnsSOARecord(serverDomain, "hostadmin." + serverDomain, 1, 14400, 3600, 604800, 60);
            _nsRecord = new DnsNSRecord(serverDomain);

            _zoneManager.ServerDomain = serverDomain;
        }

        #endregion

        #region public

        public void LoadBlockedZoneFile()
        {
            _zoneManager.Flush();

            string blockedZoneFile = Path.Combine(_dnsServer.ConfigFolder, "blocked.config");

            try
            {
                string oldCustomBlockedZoneFile = Path.Combine(_dnsServer.ConfigFolder, "custom-blocked.config");
                if (File.Exists(oldCustomBlockedZoneFile))
                {
                    if (File.Exists(blockedZoneFile))
                        File.Delete(blockedZoneFile);

                    File.Move(oldCustomBlockedZoneFile, blockedZoneFile);
                }
            }
            catch (Exception ex)
            {
                LogManager log = _dnsServer.LogManager;
                if (log != null)
                    log.Write(ex);
            }

            try
            {
                LogManager log = _dnsServer.LogManager;
                if (log != null)
                    log.Write("DNS Server is loading blocked zone file: " + blockedZoneFile);

                using (FileStream fS = new FileStream(blockedZoneFile, FileMode.Open, FileAccess.Read))
                {
                    BinaryReader bR = new BinaryReader(fS);

                    if (Encoding.ASCII.GetString(bR.ReadBytes(2)) != "BZ") //format
                        throw new InvalidDataException("DnsServer blocked zone file format is invalid.");

                    byte version = bR.ReadByte();
                    switch (version)
                    {
                        case 1:
                            int length = bR.ReadInt32();

                            for (int i = 0; i < length; i++)
                                BlockZone(bR.ReadShortString());

                            break;

                        default:
                            throw new InvalidDataException("DnsServer blocked zone file version not supported.");
                    }
                }

                if (log != null)
                    log.Write("DNS Server blocked zone file was loaded: " + blockedZoneFile);
            }
            catch (FileNotFoundException)
            { }
            catch (Exception ex)
            {
                LogManager log = _dnsServer.LogManager;
                if (log != null)
                    log.Write("DNS Server encountered an error while loading blocked zone file: " + blockedZoneFile + "\r\n" + ex.ToString());
            }
        }

        public bool BlockZone(string domain)
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

        public List<AuthZoneInfo> ListZones()
        {
            return _zoneManager.ListZones();
        }

        public void ListAllRecords(string domain, List<DnsResourceRecord> records)
        {
            _zoneManager.ListAllRecords(domain, records);
        }

        public void ListSubDomains(string domain, List<string> subDomains)
        {
            _zoneManager.ListSubDomains(domain, subDomains);
        }

        public IReadOnlyList<DnsResourceRecord> QueryRecords(string domain, DnsResourceRecordType type)
        {
            return _zoneManager.QueryRecords(domain, type);
        }

        public void SaveZoneFile()
        {
            List<AuthZoneInfo> blockedZones = _dnsServer.BlockedZoneManager.ListZones();

            string blockedZoneFile = Path.Combine(_dnsServer.ConfigFolder, "blocked.config");

            using (FileStream fS = new FileStream(blockedZoneFile, FileMode.Create, FileAccess.Write))
            {
                BinaryWriter bW = new BinaryWriter(fS);

                bW.Write(Encoding.ASCII.GetBytes("BZ")); //format
                bW.Write((byte)1); //version

                bW.Write(blockedZones.Count);

                foreach (AuthZoneInfo zone in blockedZones)
                    bW.WriteShortString(zone.Name);
            }

            LogManager log = _dnsServer.LogManager;
            if (log != null)
                log.Write("DNS Server blocked zone file was saved: " + blockedZoneFile);
        }

        public DnsDatagram Query(DnsDatagram request)
        {
            return _zoneManager.Query(request, true);
        }

        #endregion

        #region properties

        internal DnsSOARecord DnsSOARecord
        { get { return _soaRecord; } }

        public string ServerDomain
        {
            get { return _soaRecord.PrimaryNameServer; }
            set { UpdateServerDomain(value); }
        }

        public int TotalZonesBlocked
        { get { return _zoneManager.TotalZones; } }

        #endregion
    }
}
