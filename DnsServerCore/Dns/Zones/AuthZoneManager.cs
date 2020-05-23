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
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns.Zones
{
    public class AuthZoneManager
    {
        #region variables

        readonly ZoneTree<AuthZone> _root = new ZoneTree<AuthZone>();

        #endregion

        #region private

        private void CreateZone(AuthZoneInfo zoneInfo)
        {
            //create zone
            switch (zoneInfo.Type)
            {
                case AuthZoneType.Primary:
                    if (!_root.TryAdd(new PrimaryZone(zoneInfo.Name, zoneInfo.Disabled)))
                        throw new DnsServerException("Zone already exists: " + zoneInfo.Name);

                    break;

                case AuthZoneType.Secondary:
                    if (!_root.TryAdd(new SecondaryZone(zoneInfo.Name, zoneInfo.Disabled)))
                        throw new DnsServerException("Zone already exists: " + zoneInfo.Name);

                    break;

                case AuthZoneType.Stub:
                    if (!_root.TryAdd(new StubZone(zoneInfo.Name, zoneInfo.Disabled)))
                        throw new DnsServerException("Zone already exists: " + zoneInfo.Name);

                    break;

                default:
                    throw new InvalidDataException("DNS Zone type not supported.");
            }
        }

        private IReadOnlyList<DnsResourceRecord> GetAdditionalRecords(IReadOnlyList<DnsResourceRecord> nsRecords)
        {
            IReadOnlyList<DnsResourceRecord> glueRecords = nsRecords.GetGlueRecords();
            if (glueRecords.Count > 0)
                return glueRecords;

            List<DnsResourceRecord> additionalRecords = new List<DnsResourceRecord>();

            foreach (DnsResourceRecord nsRecord in nsRecords)
            {
                if (nsRecord.Type != DnsResourceRecordType.NS)
                    continue;

                AuthZone authZone = _root.FindZone((nsRecord.RDATA as DnsNSRecord).NSDomainName, out _, out _, out _);
                if ((authZone != null) && !authZone.Disabled)
                {
                    {
                        IReadOnlyList<DnsResourceRecord> records = authZone.QueryRecords(DnsResourceRecordType.A);
                        if ((records.Count > 0) && (records[0].RDATA is DnsARecord))
                            additionalRecords.AddRange(records);
                    }

                    {
                        IReadOnlyList<DnsResourceRecord> records = authZone.QueryRecords(DnsResourceRecordType.AAAA);
                        if ((records.Count > 0) && (records[0].RDATA is DnsAAAARecord))
                            additionalRecords.AddRange(records);
                    }
                }
            }

            return additionalRecords;
        }

        #endregion

        #region public

        public bool CreatePrimaryZone(string domain, string masterNameServer, bool @internal)
        {
            return _root.TryAdd(new PrimaryZone(domain, new DnsSOARecord(masterNameServer, "hostmaster." + masterNameServer, 1, 14400, 3600, 604800, 900), @internal));
        }

        public bool CreatePrimaryZone(string domain, DnsSOARecord soaRecord, DnsNSRecord ns, bool @internal)
        {
            return _root.TryAdd(new PrimaryZone(domain, soaRecord, ns, @internal));
        }

        public bool CreateSecondaryZone(string domain, string masterNameServer)
        {
            return _root.TryAdd(new SecondaryZone(domain, new DnsSOARecord(masterNameServer, "hostmaster." + masterNameServer, 1, 14400, 3600, 604800, 900)));
        }

        public bool CreateStubZone(string domain, string masterNameServer)
        {
            return _root.TryAdd(new StubZone(domain, new DnsSOARecord(masterNameServer, "hostmaster." + masterNameServer, 1, 14400, 3600, 604800, 900)));
        }

        public bool DeleteZone(string domain)
        {
            return _root.TryRemove(domain, out _);
        }

        public AuthZoneInfo GetZoneInfo(string domain)
        {
            _ = _root.FindZone(domain, out _, out AuthZone authority, out _);
            if (authority == null)
                return null;

            return new AuthZoneInfo(authority);
        }

        public bool ZoneExistsAndEnabled(string domain)
        {
            if (_root.TryGet(domain, out AuthZone zone))
                return !zone.Disabled;

            return false;
        }

        public void DisableZone(string domain)
        {
            if (_root.TryGet(domain, out AuthZone zone))
                zone.Disabled = true;
        }

        public List<DnsResourceRecord> ListAllRecords(string domain)
        {
            List<DnsResourceRecord> records = new List<DnsResourceRecord>();

            foreach (AuthZone zone in _root.GetZoneWithSubDomainZones(domain))
                records.AddRange(zone.ListAllRecords());

            return records;
        }

        public IReadOnlyList<DnsResourceRecord> QueryRecords(string domain, DnsResourceRecordType type)
        {
            if (_root.TryGet(domain, out AuthZone zone))
                return zone.QueryRecords(type);

            return Array.Empty<DnsResourceRecord>();
        }

        public List<DnsResourceRecord> GetZoneTransferRecords(string domain)
        {
            List<DnsResourceRecord> axfrRecords = new List<DnsResourceRecord>();

            List<AuthZone> zones = _root.GetZoneWithSubDomainZones(domain);

            if ((zones.Count > 0) && (zones[0] is PrimaryZone) && !zones[0].Disabled)
            {
                //only primary zones support zone transfer
                DnsResourceRecord soaRecord = zones[0].QueryRecords(DnsResourceRecordType.SOA)[0];

                axfrRecords.Add(soaRecord);

                foreach (Zone zone in zones)
                {
                    foreach (DnsResourceRecord record in zone.ListAllRecords())
                    {
                        if (record.Type != DnsResourceRecordType.SOA)
                            axfrRecords.Add(record);
                    }
                }

                axfrRecords.Add(soaRecord);
            }

            return axfrRecords;
        }

        public void SetRecords(string domain, DnsResourceRecordType type, uint ttl, DnsResourceRecordData[] records)
        {
            AuthZone zone = _root.GetOrAdd(domain, delegate (string key)
            {
                return new SubDomainZone(domain);
            });

            DnsResourceRecord[] resourceRecords = new DnsResourceRecord[records.Length];

            for (int i = 0; i < records.Length; i++)
                resourceRecords[i] = new DnsResourceRecord(zone.Name, type, DnsClass.IN, ttl, records[i]);

            zone.SetRecords(type, resourceRecords);

            if (zone is SubDomainZone)
                zone.Disabled = zone.AreAllRecordsDisabled();
        }

        public void SetRecords(IReadOnlyList<DnsResourceRecord> resourceRecords)
        {
            if (resourceRecords.Count == 1)
            {
                AuthZone zone = _root.GetOrAdd(resourceRecords[0].Name, delegate (string key)
                {
                    return new SubDomainZone(resourceRecords[0].Name);
                });

                zone.SetRecords(resourceRecords[0].Type, resourceRecords);

                if (zone is SubDomainZone)
                    zone.Disabled = zone.AreAllRecordsDisabled();
            }
            else
            {
                Dictionary<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> groupedByDomainRecords = DnsResourceRecord.GroupRecords(resourceRecords);

                //add grouped records
                foreach (KeyValuePair<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> groupedByTypeRecords in groupedByDomainRecords)
                {
                    AuthZone zone = _root.GetOrAdd(groupedByTypeRecords.Key, delegate (string key)
                    {
                        return new SubDomainZone(groupedByTypeRecords.Key);
                    });

                    foreach (KeyValuePair<DnsResourceRecordType, List<DnsResourceRecord>> groupedRecords in groupedByTypeRecords.Value)
                        zone.SetRecords(groupedRecords.Key, groupedRecords.Value);

                    if (zone is SubDomainZone)
                        zone.Disabled = zone.AreAllRecordsDisabled();
                }
            }
        }

        public void AddRecord(string domain, DnsResourceRecordType type, uint ttl, DnsResourceRecordData record)
        {
            AuthZone zone = _root.GetOrAdd(domain, delegate (string key)
            {
                return new SubDomainZone(domain);
            });

            zone.AddRecord(new DnsResourceRecord(zone.Name, type, DnsClass.IN, ttl, record));

            if (zone is SubDomainZone)
                zone.Disabled = zone.AreAllRecordsDisabled();
        }

        public void UpdateRecord(DnsResourceRecord oldRecord, DnsResourceRecord newRecord)
        {
            if (oldRecord.Type != newRecord.Type)
                throw new DnsServerException("Cannot update record: new record must be of same type.");

            if (oldRecord.Type == DnsResourceRecordType.SOA)
                throw new DnsServerException("Cannot update record: use SetRecords() for updating SOA record.");

            if (!_root.TryGet(oldRecord.Name, out AuthZone zone))
                throw new DnsServerException("Cannot update record: zone does not exists.");

            switch (oldRecord.Type)
            {
                case DnsResourceRecordType.CNAME:
                case DnsResourceRecordType.PTR:
                    if (oldRecord.Name.Equals(newRecord.Name, StringComparison.OrdinalIgnoreCase))
                    {
                        zone.SetRecords(newRecord.Type, new DnsResourceRecord[] { newRecord });

                        if (zone is SubDomainZone)
                            zone.Disabled = zone.AreAllRecordsDisabled();
                    }
                    else
                    {
                        zone.DeleteRecords(oldRecord.Type);

                        if (zone is SubDomainZone)
                        {
                            if (zone.IsEmpty)
                                _root.TryRemove(oldRecord.Name, out _); //remove empty sub zone
                            else
                                zone.Disabled = zone.AreAllRecordsDisabled();
                        }

                        AuthZone newZone = _root.GetOrAdd(newRecord.Name, delegate (string key)
                        {
                            return new SubDomainZone(newRecord.Name);
                        });

                        newZone.SetRecords(newRecord.Type, new DnsResourceRecord[] { newRecord });

                        if (newZone is SubDomainZone)
                            newZone.Disabled = zone.AreAllRecordsDisabled();
                    }
                    break;

                default:
                    if (oldRecord.Name.Equals(newRecord.Name, StringComparison.OrdinalIgnoreCase))
                    {
                        zone.DeleteRecord(oldRecord.Type, oldRecord.RDATA);
                        zone.AddRecord(newRecord);

                        if (zone is SubDomainZone)
                            zone.Disabled = zone.AreAllRecordsDisabled();
                    }
                    else
                    {
                        zone.DeleteRecord(oldRecord.Type, oldRecord.RDATA);

                        if (zone is SubDomainZone)
                        {
                            if (zone.IsEmpty)
                                _root.TryRemove(oldRecord.Name, out _); //remove empty sub zone
                            else
                                zone.Disabled = zone.AreAllRecordsDisabled();
                        }

                        AuthZone newZone = _root.GetOrAdd(newRecord.Name, delegate (string key)
                        {
                            return new SubDomainZone(newRecord.Name);
                        });

                        newZone.AddRecord(newRecord);

                        if (newZone is SubDomainZone)
                            newZone.Disabled = zone.AreAllRecordsDisabled();
                    }
                    break;
            }
        }

        public void DeleteRecord(string domain, DnsResourceRecordType type, DnsResourceRecordData record)
        {
            if (_root.TryGet(domain, out AuthZone zone))
            {
                zone.DeleteRecord(type, record);

                if (zone is SubDomainZone)
                {
                    if (zone.IsEmpty)
                        _root.TryRemove(domain, out _); //remove empty sub zone
                    else
                        zone.Disabled = zone.AreAllRecordsDisabled();
                }
            }
        }

        public void DeleteRecords(string domain, DnsResourceRecordType type)
        {
            if (_root.TryGet(domain, out AuthZone zone))
            {
                zone.DeleteRecords(type);

                if (zone is SubDomainZone)
                {
                    if (zone.IsEmpty)
                        _root.TryRemove(domain, out _); //remove empty sub zone
                    else
                        zone.Disabled = zone.AreAllRecordsDisabled();
                }
            }
        }

        public List<AuthZoneInfo> ListZones()
        {
            List<AuthZoneInfo> zones = new List<AuthZoneInfo>();

            foreach (AuthZone zone in _root)
            {
                AuthZoneInfo zoneInfo = new AuthZoneInfo(zone);
                switch (zoneInfo.Type)
                {
                    case AuthZoneType.Primary:
                    case AuthZoneType.Secondary:
                    case AuthZoneType.Stub:
                        zones.Add(zoneInfo);
                        break;
                }
            }

            return zones;
        }

        public List<string> ListSubDomains(string domain)
        {
            return _root.ListSubDomains(domain);
        }

        public DnsDatagram Query(DnsDatagram request)
        {
            AuthZone zone = _root.FindZone(request.Question[0].Name, out AuthZone delegation, out AuthZone authZone, out bool hasSubDomains);

            if ((authZone == null) || authZone.Disabled) //no authority for requested zone
                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.Refused, request.Question);

            if ((authZone is StubZone) || ((delegation != null) && !delegation.Disabled))
            {
                //zone is delegation
                IReadOnlyList<DnsResourceRecord> authority = delegation.QueryRecords(DnsResourceRecordType.NS);
                IReadOnlyList<DnsResourceRecord> additional = GetAdditionalRecords(authority);

                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.NoError, request.Question, null, authority, additional);
            }

            if ((zone == null) || zone.Disabled)
            {
                //zone not found
                DnsResponseCode rCode = hasSubDomains ? DnsResponseCode.NoError : DnsResponseCode.NameError;
                IReadOnlyList<DnsResourceRecord> authority = authZone.QueryRecords(DnsResourceRecordType.SOA);

                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, true, false, request.RecursionDesired, false, false, false, rCode, request.Question, null, authority);
            }

            //zone found
            if ((authZone is PrimaryZone) || (authZone is SecondaryZone))
            {
                IReadOnlyList<DnsResourceRecord> authority;
                IReadOnlyList<DnsResourceRecord> additional;

                IReadOnlyList<DnsResourceRecord> answers = zone.QueryRecords(request.Question[0].Type);
                if (answers.Count == 0)
                {
                    //record type not found
                    authority = authZone.QueryRecords(DnsResourceRecordType.SOA);
                    additional = null;
                }
                else
                {
                    //record type found
                    if (zone.Name.Contains("*"))
                    {
                        //wildcard zone; generate new answer records
                        DnsResourceRecord[] wildcardAnswers = new DnsResourceRecord[answers.Count];

                        for (int i = 0; i < answers.Count; i++)
                            wildcardAnswers[i] = new DnsResourceRecord(request.Question[0].Name, answers[i].Type, answers[i].Class, answers[i].TtlValue, answers[i].RDATA) { Tag = answers[i].Tag };

                        answers = wildcardAnswers;
                    }

                    switch (request.Question[0].Type)
                    {
                        case DnsResourceRecordType.NS:
                            authority = null;
                            additional = GetAdditionalRecords(answers);
                            break;

                        case DnsResourceRecordType.ANY:
                            authority = null;
                            additional = null;
                            break;

                        default:
                            authority = authZone.QueryRecords(DnsResourceRecordType.NS);
                            additional = GetAdditionalRecords(authority);
                            break;
                    }
                }

                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, true, false, request.RecursionDesired, false, false, false, DnsResponseCode.NoError, request.Question, answers, authority, additional);
            }

            //unknown zone type encountered
            return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.NotImplemented, request.Question);
        }

        public void LoadZoneFrom(Stream s)
        {
            BinaryReader bR = new BinaryReader(s);

            if (Encoding.ASCII.GetString(bR.ReadBytes(2)) != "DZ")
                throw new InvalidDataException("DnsServer zone file format is invalid.");

            switch (bR.ReadByte())
            {
                case 2:
                    {
                        DnsResourceRecord[] records = new DnsResourceRecord[bR.ReadInt32()];
                        if (records.Length > 0)
                        {
                            for (int i = 0; i < records.Length; i++)
                                records[i] = new DnsResourceRecord(s);

                            //make zone info
                            AuthZoneInfo zoneInfo = new AuthZoneInfo(records[0].Name, AuthZoneType.Primary, false);

                            //create zone
                            CreateZone(zoneInfo);

                            //set records
                            SetRecords(records);
                        }
                    }
                    break;

                case 3:
                    {
                        bool zoneDisabled = bR.ReadBoolean();
                        DnsResourceRecord[] records = new DnsResourceRecord[bR.ReadInt32()];
                        if (records.Length > 0)
                        {
                            for (int i = 0; i < records.Length; i++)
                            {
                                records[i] = new DnsResourceRecord(s);
                                records[i].Tag = new DnsResourceRecordInfo(bR);
                            }

                            //make zone info
                            AuthZoneInfo zoneInfo = new AuthZoneInfo(records[0].Name, AuthZoneType.Primary, zoneDisabled);

                            //create zone
                            CreateZone(zoneInfo);

                            //set records
                            SetRecords(records);
                        }
                    }
                    break;

                case 4:
                    {
                        //read zone info
                        AuthZoneInfo zoneInfo = new AuthZoneInfo(bR);

                        //create zone
                        CreateZone(zoneInfo);

                        //read all zone records
                        DnsResourceRecord[] records = new DnsResourceRecord[bR.ReadInt32()];
                        if (records.Length > 0)
                        {
                            for (int i = 0; i < records.Length; i++)
                            {
                                records[i] = new DnsResourceRecord(s);
                                records[i].Tag = new DnsResourceRecordInfo(bR);
                            }

                            //set records
                            SetRecords(records);
                        }
                    }
                    break;

                default:
                    throw new InvalidDataException("DNS Zone file version not supported.");
            }
        }

        public void WriteZoneTo(string domain, Stream s)
        {
            List<AuthZone> zones = _root.GetZoneWithSubDomainZones(domain);
            if (zones.Count == 0)
                throw new DnsServerException("Zone was not found: " + domain);

            //serialize zone
            BinaryWriter bW = new BinaryWriter(s);

            bW.Write(Encoding.ASCII.GetBytes("DZ")); //format
            bW.Write((byte)4); //version

            //write zone info
            AuthZoneInfo zoneInfo = new AuthZoneInfo(zones[0]);
            zoneInfo.WriteTo(bW);

            //write all zone records
            List<DnsResourceRecord> records = new List<DnsResourceRecord>();

            foreach (AuthZone zone in zones)
                records.AddRange(zone.ListAllRecords());

            bW.Write(records.Count);

            foreach (DnsResourceRecord record in records)
            {
                record.WriteTo(s);

                DnsResourceRecordInfo rrInfo = record.Tag as DnsResourceRecordInfo;
                if (rrInfo == null)
                    rrInfo = new DnsResourceRecordInfo(); //default info

                rrInfo.WriteTo(bW);
            }
        }

        #endregion
    }
}
