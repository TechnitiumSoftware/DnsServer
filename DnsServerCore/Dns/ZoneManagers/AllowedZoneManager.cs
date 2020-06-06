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

using DnsServerCore.Dns.Zones;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns.ZoneManagers
{
    public class AllowedZoneManager
    {
        #region variables

        readonly DnsServer _dnsServer;

        readonly AuthZoneManager _zoneManager = new AuthZoneManager(null);

        DnsSOARecord _soaRecord;
        DnsNSRecord _nsRecord;

        int _totalZonesAllowed;

        #endregion

        #region constructor

        public AllowedZoneManager(DnsServer dnsServer)
        {
            _dnsServer = dnsServer;

            UpdateServerDomain(_dnsServer.ServerDomain);
            LoadZoneFile();
        }

        #endregion

        #region private

        private void UpdateServerDomain(string serverDomain)
        {
            _soaRecord = new DnsSOARecord(serverDomain, "hostmaster." + serverDomain, 1, 14400, 3600, 604800, 900);
            _nsRecord = new DnsNSRecord(serverDomain);
        }

        private void LoadZoneFile()
        {
            string allowedZoneFile = Path.Combine(_dnsServer.ConfigFolder, "allowed.config");

            try
            {
                LogManager log = _dnsServer.LogManager;
                if (log != null)
                    log.Write("DNS Server is loading allowed zone file: " + allowedZoneFile);

                using (FileStream fS = new FileStream(allowedZoneFile, FileMode.Open, FileAccess.Read))
                {
                    BinaryReader bR = new BinaryReader(fS);

                    if (Encoding.ASCII.GetString(bR.ReadBytes(2)) != "AZ") //format
                        throw new InvalidDataException("DnsServer allowed zone file format is invalid.");

                    byte version = bR.ReadByte();
                    switch (version)
                    {
                        case 1:
                            int length = bR.ReadInt32();

                            for (int i = 0; i < length; i++)
                                AllowZone(bR.ReadShortString());

                            break;

                        default:
                            throw new InvalidDataException("DnsServer allowed zone file version not supported.");
                    }
                }

                if (log != null)
                    log.Write("DNS Server allowed zone file was loaded: " + allowedZoneFile);
            }
            catch (FileNotFoundException)
            { }
            catch (Exception ex)
            {
                LogManager log = _dnsServer.LogManager;
                if (log != null)
                    log.Write("DNS Server encountered an error while loading allowed zone file: " + allowedZoneFile + "\r\n" + ex.ToString());
            }
        }

        #endregion

        #region public

        public void AllowZone(string domain)
        {
            if (_zoneManager.CreatePrimaryZone(domain, _soaRecord, _nsRecord, false) != null)
                _totalZonesAllowed++;
        }

        public void DeleteZone(string domain)
        {
            if (_zoneManager.DeleteZone(domain))
                _totalZonesAllowed--;
        }

        public List<AuthZoneInfo> ListZones()
        {
            return _zoneManager.ListZones();
        }

        public List<string> ListSubDomains(string domain)
        {
            return _zoneManager.ListSubDomains(domain);
        }

        public IReadOnlyList<DnsResourceRecord> QueryRecords(string domain, DnsResourceRecordType type)
        {
            return _zoneManager.QueryRecords(domain, type);
        }

        public void SaveZoneFile()
        {
            List<AuthZoneInfo> allowedZones = _dnsServer.AllowedZoneManager.ListZones();

            _totalZonesAllowed = allowedZones.Count;

            string allowedZoneFile = Path.Combine(_dnsServer.ConfigFolder, "allowed.config");

            using (FileStream fS = new FileStream(allowedZoneFile, FileMode.Create, FileAccess.Write))
            {
                BinaryWriter bW = new BinaryWriter(fS);

                bW.Write(Encoding.ASCII.GetBytes("AZ")); //format
                bW.Write((byte)1); //version

                bW.Write(allowedZones.Count);

                foreach (AuthZoneInfo zone in allowedZones)
                    bW.WriteShortString(zone.Name);
            }

            LogManager log = _dnsServer.LogManager;
            if (log != null)
                log.Write("DNS Server allowed zone file was saved: " + allowedZoneFile);
        }

        public DnsDatagram Query(DnsDatagram request)
        {
            return _zoneManager.Query(request);
        }

        #endregion

        #region properties

        public string ServerDomain
        {
            get { return _soaRecord.MasterNameServer; }
            set { UpdateServerDomain(value); }
        }

        public int TotalZonesAllowed
        { get { return _totalZonesAllowed; } }

        #endregion
    }
}
