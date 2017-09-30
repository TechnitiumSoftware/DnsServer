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
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using TechnitiumLibrary.Net.Dns;

namespace DnsServerCore
{
    public class Zone
    {
        #region variables

        const uint DEFAULT_RECORD_TTL = 60u;

        readonly bool _authoritativeZone;

        readonly Zone _parentZone;
        readonly string _zoneName;

        readonly ConcurrentDictionary<string, Zone> _zones = new ConcurrentDictionary<string, Zone>();
        readonly ConcurrentDictionary<DnsResourceRecordType, DnsResourceRecord[]> _entries = new ConcurrentDictionary<DnsResourceRecordType, DnsResourceRecord[]>();

        #endregion

        #region constructor

        public Zone(bool authoritativeZone)
        {
            _authoritativeZone = authoritativeZone;
            _zoneName = "";

            if (!_authoritativeZone)
                LoadRootHintsInCache();
        }

        private Zone(Zone parentZone, string zoneLabel)
        {
            _authoritativeZone = parentZone._authoritativeZone;
            _parentZone = parentZone;

            string zoneName = zoneLabel;

            if (_parentZone._zoneName != "")
                zoneName += "." + _parentZone._zoneName;

            _zoneName = zoneName;
        }

        #endregion

        #region private

        private void LoadRootHintsInCache()
        {
            List<DnsResourceRecord> nsRecords = new List<DnsResourceRecord>(13);

            foreach (NameServerAddress rootNameServer in DnsClient.ROOT_NAME_SERVERS_IPv4)
            {
                nsRecords.Add(new DnsResourceRecord("", DnsResourceRecordType.NS, DnsClass.IN, 172800, new DnsNSRecord(rootNameServer.Domain)));

                CreateZone(this, rootNameServer.Domain).SetRecord(DnsResourceRecordType.A, new DnsResourceRecord[] { new DnsResourceRecord(rootNameServer.Domain, DnsResourceRecordType.A, DnsClass.IN, 172800, new DnsARecord(rootNameServer.EndPoint.Address)) });
            }

            foreach (NameServerAddress rootNameServer in DnsClient.ROOT_NAME_SERVERS_IPv6)
            {
                CreateZone(this, rootNameServer.Domain).SetRecord(DnsResourceRecordType.AAAA, new DnsResourceRecord[] { new DnsResourceRecord(rootNameServer.Domain, DnsResourceRecordType.AAAA, DnsClass.IN, 172800, new DnsARecord(rootNameServer.EndPoint.Address)) });
            }

            SetRecord(DnsResourceRecordType.NS, nsRecords.ToArray());
        }

        private static string[] ConvertDomainToPath(string domainName)
        {
            if (string.IsNullOrEmpty(domainName))
                return new string[] { };

            string[] path = domainName.ToLower().Split('.');
            Array.Reverse(path);

            return path;
        }

        private static Zone CreateZone(Zone rootZone, string domain)
        {
            Zone currentZone = rootZone;
            string[] path = ConvertDomainToPath(domain);

            for (int i = 0; i < path.Length; i++)
            {
                string nextZoneLabel = path[i];

                Zone nextZone = currentZone._zones.GetOrAdd(nextZoneLabel, delegate (string key)
                {
                    return new Zone(currentZone, nextZoneLabel);
                });

                currentZone = nextZone;
            }

            return currentZone;
        }

        private static Zone FindClosestZone(Zone rootZone, string domain)
        {
            Zone currentZone = rootZone;
            string[] path = ConvertDomainToPath(domain);

            for (int i = 0; i < path.Length; i++)
            {
                string nextZoneName = path[i];

                if (currentZone._zones.TryGetValue(nextZoneName, out Zone nextZone))
                    currentZone = nextZone;
                else
                    return currentZone;
            }

            return currentZone;
        }

        private static Zone DeleteZone(Zone rootZone, string domain)
        {
            Zone currentZone = rootZone;
            string[] path = ConvertDomainToPath(domain);

            //find parent zone
            for (int i = 0; i < path.Length - 1; i++)
            {
                string nextZoneName = path[i];

                if (currentZone._zones.TryGetValue(nextZoneName, out Zone nextZone))
                    currentZone = nextZone;
                else
                    return null;
            }

            if (currentZone._zones.TryRemove(path[path.Length - 1], out Zone deletedZone))
                return deletedZone;

            return null;
        }

        private static DnsResourceRecord[] GetRecords(Zone rootZone, string domain, DnsResourceRecordType type)
        {
            Zone closestZone = FindClosestZone(rootZone, domain);

            if (closestZone._zoneName.Equals(domain, StringComparison.CurrentCultureIgnoreCase))
                return closestZone.GetRecords(type);

            return null;
        }

        private void SetRecord(DnsResourceRecordType type, DnsResourceRecord[] records)
        {
            DnsResourceRecord[] existingRecords = _entries.GetOrAdd(type, delegate (DnsResourceRecordType key)
            {
                return records;
            });
        }

        private DnsResourceRecord[] GetRecords(DnsResourceRecordType type)
        {
            if (_entries.TryGetValue(DnsResourceRecordType.CNAME, out DnsResourceRecord[] existingCNAMERecords))
                return existingCNAMERecords;

            if ((type == DnsResourceRecordType.ANY) && _authoritativeZone)
            {
                List<DnsResourceRecord> allRecords = new List<DnsResourceRecord>();

                foreach (KeyValuePair<DnsResourceRecordType, DnsResourceRecord[]> entry in _entries)
                    allRecords.AddRange(entry.Value);

                return allRecords.ToArray();
            }

            if (_entries.TryGetValue(type, out DnsResourceRecord[] existingRecords))
                return existingRecords;

            return null;
        }

        private DnsResourceRecord[] GetClosestNameServers()
        {
            Zone currentZone = this;
            DnsResourceRecord[] nsRecords = null;

            while (currentZone != null)
            {
                nsRecords = currentZone.GetRecords(DnsResourceRecordType.NS);
                if (nsRecords != null)
                    return nsRecords;

                currentZone = currentZone._parentZone;
            }

            return null;
        }

        private DnsResourceRecord[] GetClosestAuthority()
        {
            Zone currentZone = this;
            DnsResourceRecord[] nsRecords = null;

            while (currentZone != null)
            {
                nsRecords = currentZone.GetRecords(DnsResourceRecordType.SOA);
                if (nsRecords != null)
                    return nsRecords;

                currentZone = currentZone._parentZone;
            }

            return null;
        }

        private void GetAuthoritativeZones(List<Zone> zones)
        {
            if (GetRecords(DnsResourceRecordType.SOA) != null)
                zones.Add(this);

            foreach (KeyValuePair<string, Zone> entry in _zones)
            {
                entry.Value.GetAuthoritativeZones(zones);
            }
        }

        private static DnsDatagram QueryAuthoritative(Zone rootZone, DnsDatagram request)
        {
            DnsQuestionRecord question = request.Question[0];
            string domain = question.Name.ToLower();

            Zone closestZone = FindClosestZone(rootZone, domain);

            if (closestZone._zoneName.Equals(domain))
            {
                //zone found
                DnsResourceRecord[] records = closestZone.GetRecords(question.Type);
                if (records == null)
                {
                    //record type not found
                    DnsResourceRecord[] closestAuthority = closestZone.GetClosestAuthority();

                    if (closestAuthority == null)
                        return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, false, false, request.Header.RecursionDesired, false, false, false, DnsResponseCode.Refused, 1, 0, 0, 0), request.Question, new DnsResourceRecord[] { }, new DnsResourceRecord[] { }, new DnsResourceRecord[] { });

                    return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, true, false, request.Header.RecursionDesired, false, false, false, DnsResponseCode.NoError, 1, 0, 1, 0), request.Question, new DnsResourceRecord[] { }, closestAuthority, new DnsResourceRecord[] { });
                }
                else
                {
                    //record type found

                    if ((records.Length > 0) && (records[0].Type == DnsResourceRecordType.CNAME))
                        records = ResolveCNAME(rootZone, records[0], question.Type);

                    return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, true, false, request.Header.RecursionDesired, false, false, false, DnsResponseCode.NoError, 1, (ushort)records.Length, 0, 0), request.Question, records, new DnsResourceRecord[] { }, new DnsResourceRecord[] { });
                }
            }
            else
            {
                //zone doesnt exists
                DnsResourceRecord[] closestAuthority = closestZone.GetClosestAuthority();

                if (closestAuthority == null)
                    return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, false, false, request.Header.RecursionDesired, false, false, false, DnsResponseCode.Refused, 1, 0, 0, 0), request.Question, new DnsResourceRecord[] { }, new DnsResourceRecord[] { }, new DnsResourceRecord[] { });

                return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, true, false, request.Header.RecursionDesired, false, false, false, DnsResponseCode.NameError, 1, 0, 1, 0), request.Question, new DnsResourceRecord[] { }, closestAuthority, new DnsResourceRecord[] { });
            }
        }

        private static DnsDatagram QueryCache(Zone rootZone, DnsDatagram request)
        {
            DnsQuestionRecord question = request.Question[0];
            string domain = question.Name.ToLower();

            Zone closestZone = FindClosestZone(rootZone, domain);

            if (closestZone._zoneName.Equals(domain))
            {
                DnsResourceRecord[] records = closestZone.GetRecords(question.Type);
                if (records != null)
                {
                    if (records[0].RDATA is DnsEmptyRecord)
                        return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, false, false, request.Header.RecursionDesired, true, false, false, DnsResponseCode.NoError, 1, 0, 1, 0), request.Question, new DnsResourceRecord[] { }, new DnsResourceRecord[] { (records[0].RDATA as DnsEmptyRecord).Authority }, new DnsResourceRecord[] { });

                    if (records[0].RDATA is DnsNXRecord)
                        return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, false, false, request.Header.RecursionDesired, true, false, false, DnsResponseCode.NameError, 1, 0, 1, 0), request.Question, new DnsResourceRecord[] { }, new DnsResourceRecord[] { (records[0].RDATA as DnsNXRecord).Authority }, new DnsResourceRecord[] { });

                    if ((records.Length > 0) && (records[0].Type == DnsResourceRecordType.CNAME))
                        records = ResolveCNAME(rootZone, records[0], question.Type);

                    return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, false, false, request.Header.RecursionDesired, true, false, false, DnsResponseCode.NoError, 1, (ushort)records.Length, 0, 0), request.Question, records, new DnsResourceRecord[] { }, new DnsResourceRecord[] { });
                }
            }

            DnsResourceRecord[] nameServers = closestZone.GetClosestNameServers();
            if (nameServers != null)
            {
                List<DnsResourceRecord> glueRecords = new List<DnsResourceRecord>();

                foreach (DnsResourceRecord nameServer in nameServers)
                {
                    string nsDomain = (nameServer.RDATA as DnsNSRecord).NSDomainName;

                    DnsResourceRecord[] glueAs = GetRecords(rootZone, nsDomain, DnsResourceRecordType.A);
                    if (glueAs != null)
                        glueRecords.AddRange(glueAs);

                    DnsResourceRecord[] glueAAAAs = GetRecords(rootZone, nsDomain, DnsResourceRecordType.AAAA);
                    if (glueAAAAs != null)
                        glueRecords.AddRange(glueAAAAs);
                }

                DnsResourceRecord[] additional = glueRecords.ToArray();

                return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, false, false, request.Header.RecursionDesired, true, false, false, DnsResponseCode.NoError, 1, 0, (ushort)nameServers.Length, (ushort)additional.Length), request.Question, new DnsResourceRecord[] { }, nameServers, additional);
            }

            return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, false, false, request.Header.RecursionDesired, true, false, false, DnsResponseCode.Refused, 1, 0, 0, 0), request.Question, new DnsResourceRecord[] { }, new DnsResourceRecord[] { }, new DnsResourceRecord[] { });
        }

        private static DnsResourceRecord[] ResolveCNAME(Zone rootZone, DnsResourceRecord cnameRR, DnsResourceRecordType type)
        {
            if ((type == DnsResourceRecordType.CNAME) || (type == DnsResourceRecordType.ANY))
                return new DnsResourceRecord[] { cnameRR };

            List<DnsResourceRecord> recordsList = new List<DnsResourceRecord>();
            recordsList.Add(cnameRR);

            while (true)
            {
                DnsResourceRecord[] records = GetRecords(rootZone, (cnameRR.RDATA as DnsCNAMERecord).CNAMEDomainName, type);

                if ((records == null) || (records.Length == 0))
                    break;

                recordsList.AddRange(records);

                if (records[0].Type != DnsResourceRecordType.CNAME)
                    break;

                cnameRR = records[0];
            }

            return recordsList.ToArray();
        }

        #endregion

        #region internal

        internal DnsDatagram Query(DnsDatagram request)
        {
            if (_authoritativeZone)
                return QueryAuthoritative(this, request);

            return QueryCache(this, request);
        }

        internal void CacheResponse(DnsDatagram response)
        {
            if (!response.Header.IsResponse)
                return;

            //combine all records in the response
            List<DnsResourceRecord> allRecords = new List<DnsResourceRecord>();

            switch (response.Header.RCODE)
            {
                case DnsResponseCode.NameError:
                    if (response.Authority.Length > 0)
                    {
                        DnsResourceRecord authority = response.Authority[0];
                        if (authority.Type == DnsResourceRecordType.SOA)
                        {
                            foreach (DnsQuestionRecord question in response.Question)
                            {
                                DnsResourceRecord record = new DnsResourceRecord(question.Name, question.Type, DnsClass.IN, DEFAULT_RECORD_TTL, new DnsNXRecord(authority));
                                record.SetExpiry();

                                CreateZone(this, question.Name).SetRecord(question.Type, new DnsResourceRecord[] { record });
                            }
                        }
                    }
                    break;

                case DnsResponseCode.NoError:
                    if ((response.Answer.Length == 0) && (response.Authority.Length > 0))
                    {
                        DnsResourceRecord authority = response.Authority[0];
                        if (authority.Type == DnsResourceRecordType.SOA)
                        {
                            foreach (DnsQuestionRecord question in response.Question)
                            {
                                DnsResourceRecord record = new DnsResourceRecord(question.Name, question.Type, DnsClass.IN, DEFAULT_RECORD_TTL, new DnsEmptyRecord(authority));
                                record.SetExpiry();

                                CreateZone(this, question.Name).SetRecord(question.Type, new DnsResourceRecord[] { record });
                            }
                        }
                    }
                    else
                    {
                        allRecords.AddRange(response.Answer);
                    }

                    break;

                default:
                    return; //nothing to do
            }

            allRecords.AddRange(response.Authority);
            allRecords.AddRange(response.Additional);

            #region group all records by domain and type

            Dictionary<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> cacheEntries = new Dictionary<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>>();

            foreach (DnsResourceRecord record in allRecords)
            {
                Dictionary<DnsResourceRecordType, List<DnsResourceRecord>> cacheTypeEntries;

                if (cacheEntries.ContainsKey(record.Name))
                {
                    cacheTypeEntries = cacheEntries[record.Name];
                }
                else
                {
                    cacheTypeEntries = new Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>();
                    cacheEntries.Add(record.Name, cacheTypeEntries);
                }

                List<DnsResourceRecord> cacheRREntries;

                if (cacheTypeEntries.ContainsKey(record.Type))
                {
                    cacheRREntries = cacheTypeEntries[record.Type];
                }
                else
                {
                    cacheRREntries = new List<DnsResourceRecord>();
                    cacheTypeEntries.Add(record.Type, cacheRREntries);
                }

                cacheRREntries.Add(record);
            }

            #endregion

            //add grouped entries into cache
            foreach (KeyValuePair<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> cacheEntry in cacheEntries)
            {
                string domain = cacheEntry.Key;

                foreach (KeyValuePair<DnsResourceRecordType, List<DnsResourceRecord>> cacheTypeEntry in cacheEntry.Value)
                {
                    DnsResourceRecordType type = cacheTypeEntry.Key;
                    DnsResourceRecord[] records = cacheTypeEntry.Value.ToArray();

                    foreach (DnsResourceRecord record in records)
                        record.SetExpiry();

                    CreateZone(this, domain).SetRecord(type, records);
                }
            }

            //cache for ANY request
            if (response.Question[0].Type == DnsResourceRecordType.ANY)
                CreateZone(this, response.Question[0].Name).SetRecord(DnsResourceRecordType.ANY, response.Answer);
        }

        #endregion

        #region public

        public void SetRecord(string domain, DnsResourceRecordType type, uint ttl, DnsResourceRecordData[] records)
        {
            DnsResourceRecord[] resourceRecords = new DnsResourceRecord[records.Length];

            for (int i = 0; i < records.Length; i++)
                resourceRecords[i] = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, records[i]);

            CreateZone(this, domain).SetRecord(type, resourceRecords);
        }

        public DnsResourceRecord[] GetAllRecords(string domain = "")
        {
            Zone currentZone = this;

            string[] path = ConvertDomainToPath(domain);

            for (int i = 0; i < path.Length; i++)
            {
                string nextZoneName = path[i];

                if (currentZone._zones.TryGetValue(nextZoneName, out Zone nextZone))
                    currentZone = nextZone;
                else
                    return new DnsResourceRecord[] { }; //no zone for given domain
            }

            return currentZone.GetRecords(DnsResourceRecordType.ANY);
        }

        public string[] ListSubZones(string domain = "")
        {
            Zone currentZone = this;

            string[] path = ConvertDomainToPath(domain);

            for (int i = 0; i < path.Length; i++)
            {
                string nextZoneName = path[i];

                if (currentZone._zones.TryGetValue(nextZoneName, out Zone nextZone))
                    currentZone = nextZone;
                else
                    return new string[] { }; //no zone for given domain
            }

            string[] subZoneNames = new string[currentZone._zones.Keys.Count];
            currentZone._zones.Keys.CopyTo(subZoneNames, 0);

            return subZoneNames;
        }

        public string[] ListAllAuthoritativeZones(string domain = "")
        {
            Zone currentZone = this;

            string[] path = ConvertDomainToPath(domain);

            for (int i = 0; i < path.Length; i++)
            {
                string nextZoneName = path[i];

                if (currentZone._zones.TryGetValue(nextZoneName, out Zone nextZone))
                    currentZone = nextZone;
                else
                    return new string[] { }; //no zone for given domain
            }

            List<Zone> zones = new List<Zone>();
            currentZone.GetAuthoritativeZones(zones);

            List<string> zoneNames = new List<string>();

            foreach (Zone zone in zones)
                zoneNames.Add(zone._zoneName);

            return zoneNames.ToArray();
        }

        #endregion

        class DnsNXRecord : DnsResourceRecordData
        {
            #region variables

            DnsResourceRecord _authority;

            #endregion

            #region constructor

            public DnsNXRecord(DnsResourceRecord authority)
            {
                _authority = authority;
            }

            public DnsNXRecord(Stream s)
                : base(s)
            { }

            #endregion

            #region protected

            protected override void Parse(Stream s)
            { }

            protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries)
            { }

            #endregion

            #region properties

            public DnsResourceRecord Authority
            { get { return _authority; } }

            #endregion
        }

        class DnsEmptyRecord : DnsResourceRecordData
        {
            #region variables

            DnsResourceRecord _authority;

            #endregion

            #region constructor

            public DnsEmptyRecord(DnsResourceRecord authority)
            {
                _authority = authority;
            }

            public DnsEmptyRecord(Stream s)
                : base(s)
            { }

            #endregion

            #region protected

            protected override void Parse(Stream s)
            { }

            protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries)
            { }

            #endregion

            #region properties

            public DnsResourceRecord Authority
            { get { return _authority; } }

            #endregion
        }
    }
}
