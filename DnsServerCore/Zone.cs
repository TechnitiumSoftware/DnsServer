/*
Technitium DNS Server
Copyright (C) 2019  Shreyas Zare (shreyas@technitium.com)

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
        const uint MINIMUM_RECORD_TTL = 0u;

        readonly bool _authoritativeZone;

        readonly Zone _parentZone;
        readonly string _zoneLabel;
        readonly string _zoneName;

        bool _disabled;

        readonly ConcurrentDictionary<string, Zone> _zones = new ConcurrentDictionary<string, Zone>();
        readonly ConcurrentDictionary<DnsResourceRecordType, DnsResourceRecord[]> _entries = new ConcurrentDictionary<DnsResourceRecordType, DnsResourceRecord[]>();

        string _serverDomain;
        uint _serveStaleTtl;

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
            _zoneLabel = zoneLabel;

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
                nsRecords.Add(new DnsResourceRecord("", DnsResourceRecordType.NS, DnsClass.IN, 172800, new DnsNSRecord(rootNameServer.Host)));

                CreateZone(this, rootNameServer.Host).SetRecords(DnsResourceRecordType.A, new DnsResourceRecord[] { new DnsResourceRecord(rootNameServer.Host, DnsResourceRecordType.A, DnsClass.IN, 172800, new DnsARecord(rootNameServer.IPEndPoint.Address)) });
            }

            foreach (NameServerAddress rootNameServer in DnsClient.ROOT_NAME_SERVERS_IPv6)
            {
                CreateZone(this, rootNameServer.Host).SetRecords(DnsResourceRecordType.AAAA, new DnsResourceRecord[] { new DnsResourceRecord(rootNameServer.Host, DnsResourceRecordType.AAAA, DnsClass.IN, 172800, new DnsAAAARecord(rootNameServer.IPEndPoint.Address)) });
            }

            SetRecords(DnsResourceRecordType.NS, nsRecords.ToArray());
        }

        private static string[] ConvertDomainToPath(string domainName)
        {
            DnsClient.IsDomainNameValid(domainName, true);

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

        private static Zone GetZone(Zone rootZone, string domain, bool authoritative)
        {
            Zone currentZone = rootZone;
            Zone authoritativeZone = null;

            if (authoritative && currentZone._entries.ContainsKey(DnsResourceRecordType.SOA))
                authoritativeZone = currentZone;

            string[] path = ConvertDomainToPath(domain);

            for (int i = 0; i < path.Length; i++)
            {
                string nextZoneLabel = path[i];

                if (currentZone._zones.TryGetValue(nextZoneLabel, out Zone nextZone))
                {
                    currentZone = nextZone;
                }
                else
                {
                    if (authoritative)
                        return authoritativeZone;

                    return null;
                }

                if (authoritative && currentZone._entries.ContainsKey(DnsResourceRecordType.SOA))
                    authoritativeZone = currentZone;
            }

            if (authoritative)
                return authoritativeZone;

            return currentZone;
        }

        private static bool DeleteZone(Zone rootZone, string domain, bool deleteSubZones)
        {
            Zone currentZone = GetZone(rootZone, domain, false);
            if (currentZone == null)
                return false;

            if (!currentZone._authoritativeZone && (currentZone._zoneName.Equals("root-servers.net", StringComparison.OrdinalIgnoreCase)))
                return false; //cannot delete root-servers.net

            currentZone._entries.Clear();

            DeleteSubZones(currentZone, deleteSubZones);
            DeleteEmptyParentZones(currentZone);

            return true;
        }

        private static bool DeleteSubZones(Zone currentZone, bool deleteSubZones)
        {
            if (currentZone._authoritativeZone)
            {
                if (!deleteSubZones && currentZone._entries.ContainsKey(DnsResourceRecordType.SOA))
                    return false; //this is a zone so return false
            }
            else
            {
                //cache zone
                if (currentZone._zoneName.Equals("root-servers.net", StringComparison.OrdinalIgnoreCase))
                    return false; //cannot delete root-servers.net
            }

            currentZone._entries.Clear();

            List<Zone> subDomainsToDelete = new List<Zone>();

            foreach (KeyValuePair<string, Zone> zone in currentZone._zones)
            {
                if (DeleteSubZones(zone.Value, deleteSubZones))
                    subDomainsToDelete.Add(zone.Value);
            }

            foreach (Zone subDomain in subDomainsToDelete)
                currentZone._zones.TryRemove(subDomain._zoneLabel, out Zone deletedValue);

            return (currentZone._zones.Count == 0);
        }

        private static void DeleteEmptyParentZones(Zone currentZone)
        {
            while (currentZone._parentZone != null)
            {
                if ((currentZone._entries.Count > 0) || (currentZone._zones.Count > 0))
                    break;

                currentZone._parentZone._zones.TryRemove(currentZone._zoneLabel, out _);

                currentZone = currentZone._parentZone;
            }
        }

        private static void RemoveExpiredCachedRecords(Zone currentZone)
        {
            //remove expired entries in current zone
            {
                List<KeyValuePair<DnsResourceRecordType, DnsResourceRecord[]>> updateEntries = null;

                foreach (KeyValuePair<DnsResourceRecordType, DnsResourceRecord[]> entry in currentZone._entries)
                {
                    foreach (DnsResourceRecord record in entry.Value)
                    {
                        if (record.TtlValue < 1u)
                        {
                            //create new entry
                            if (updateEntries == null)
                                updateEntries = new List<KeyValuePair<DnsResourceRecordType, DnsResourceRecord[]>>();

                            List<DnsResourceRecord> newRecords = new List<DnsResourceRecord>(entry.Value.Length);

                            foreach (DnsResourceRecord existingRecord in entry.Value)
                            {
                                if (existingRecord.TtlValue < 1u)
                                    continue;

                                newRecords.Add(existingRecord);
                            }

                            updateEntries.Add(new KeyValuePair<DnsResourceRecordType, DnsResourceRecord[]>(entry.Key, newRecords.ToArray()));
                            break;
                        }
                    }
                }

                if (updateEntries != null)
                {
                    foreach (KeyValuePair<DnsResourceRecordType, DnsResourceRecord[]> updateEntry in updateEntries)
                    {
                        if (updateEntry.Value.Length > 0)
                        {
                            currentZone._entries.AddOrUpdate(updateEntry.Key, updateEntry.Value, delegate (DnsResourceRecordType key, DnsResourceRecord[] existingRecords)
                            {
                                return updateEntry.Value;
                            });
                        }
                        else
                        {
                            currentZone._entries.TryRemove(updateEntry.Key, out DnsResourceRecord[] removedValues);
                        }
                    }
                }
            }

            //remove expired entries in sub zones
            {
                List<string> subZonesToRemove = null;

                foreach (KeyValuePair<string, Zone> zone in currentZone._zones)
                {
                    RemoveExpiredCachedRecords(zone.Value);

                    if ((zone.Value._zones.Count == 0) && (zone.Value._entries.Count == 0))
                    {
                        if (subZonesToRemove == null)
                            subZonesToRemove = new List<string>();

                        subZonesToRemove.Add(zone.Key);
                    }
                }

                if (subZonesToRemove != null)
                {
                    foreach (string subZone in subZonesToRemove)
                        currentZone._zones.TryRemove(subZone, out Zone value);
                }
            }
        }

        private DnsResourceRecord[] QueryRecords(DnsResourceRecordType type, bool bypassCNAME, bool serveStale)
        {
            if (_authoritativeZone && (type == DnsResourceRecordType.ANY))
            {
                List<DnsResourceRecord> allRecords = new List<DnsResourceRecord>();

                foreach (KeyValuePair<DnsResourceRecordType, DnsResourceRecord[]> entry in _entries)
                    allRecords.AddRange(entry.Value);

                return FilterExpiredDisabledRecords(allRecords.ToArray(), serveStale);
            }

            if (!bypassCNAME && _entries.TryGetValue(DnsResourceRecordType.CNAME, out DnsResourceRecord[] existingCNAMERecords))
            {
                DnsResourceRecord[] records = FilterExpiredDisabledRecords(existingCNAMERecords, serveStale);
                if (records != null)
                    return records;
            }

            if (_entries.TryGetValue(type, out DnsResourceRecord[] existingRecords))
            {
                DnsResourceRecord[] records = FilterExpiredDisabledRecords(existingRecords, serveStale);

                if (records != null)
                    DnsClient.ShuffleArray(records); //shuffle records to allow load balancing

                return records;
            }

            return null;
        }

        private DnsResourceRecord[] GetAllRecords(DnsResourceRecordType type, bool includeSubDomains)
        {
            List<DnsResourceRecord> allRecords = new List<DnsResourceRecord>();

            foreach (KeyValuePair<DnsResourceRecordType, DnsResourceRecord[]> entry in _entries)
            {
                if (entry.Key != DnsResourceRecordType.ANY)
                {
                    if ((type == DnsResourceRecordType.ANY) || (entry.Key == type))
                        allRecords.AddRange(entry.Value);
                }
            }

            if (includeSubDomains)
            {
                foreach (KeyValuePair<string, Zone> zone in _zones)
                {
                    if (!zone.Value._entries.ContainsKey(DnsResourceRecordType.SOA))
                        allRecords.AddRange(zone.Value.GetAllRecords(type, true));
                }
            }

            return allRecords.ToArray();
        }

        private void ListAuthoritativeZones(List<Zone> zones)
        {
            DnsResourceRecord[] soa = QueryRecords(DnsResourceRecordType.SOA, true, false);
            if (soa != null)
                zones.Add(this);

            foreach (KeyValuePair<string, Zone> entry in _zones)
                entry.Value.ListAuthoritativeZones(zones);
        }

        private void SetRecords(DnsResourceRecordType type, DnsResourceRecord[] records)
        {
            _entries.AddOrUpdate(type, records, delegate (DnsResourceRecordType key, DnsResourceRecord[] existingRecords)
            {
                return records;
            });

            if (!_authoritativeZone)
            {
                //this is only applicable for cache zone 
                switch (type)
                {
                    case DnsResourceRecordType.CNAME:
                    case DnsResourceRecordType.SOA:
                    case DnsResourceRecordType.NS:
                        //do nothing
                        break;

                    default:
                        //remove old CNAME entry since current new entry type overlaps any existing CNAME entry in cache
                        //keeping both entries will create issue with serve stale implementation since stale CNAME entry will be always returned
                        _entries.TryRemove(DnsResourceRecordType.CNAME, out DnsResourceRecord[] existingValues);
                        break;
                }
            }
        }

        private void AddRecord(DnsResourceRecord record)
        {
            switch (record.Type)
            {
                case DnsResourceRecordType.CNAME:
                case DnsResourceRecordType.PTR:
                case DnsResourceRecordType.SOA:
                    throw new DnsServerException("Cannot add record: use SetRecords() for " + record.Type.ToString() + " record");
            }

            _entries.AddOrUpdate(record.Type, new DnsResourceRecord[] { record }, delegate (DnsResourceRecordType key, DnsResourceRecord[] existingRecords)
            {
                foreach (DnsResourceRecord existingRecord in existingRecords)
                {
                    if (record.RDATA.Equals(existingRecord.RDATA))
                        return existingRecords;
                }

                DnsResourceRecord[] newValue = new DnsResourceRecord[existingRecords.Length + 1];
                existingRecords.CopyTo(newValue, 0);

                newValue[newValue.Length - 1] = record;

                return newValue;
            });
        }

        private void DeleteRecord(DnsResourceRecord record)
        {
            if (_entries.TryGetValue(record.Type, out DnsResourceRecord[] existingRecords))
            {
                bool recordFound = false;

                for (int i = 0; i < existingRecords.Length; i++)
                {
                    if (record.RDATA.Equals(existingRecords[i].RDATA))
                    {
                        existingRecords[i] = null;
                        recordFound = true;
                        break;
                    }
                }

                if (!recordFound)
                    throw new DnsServerException("Resource record does not exists.");

                if (existingRecords.Length == 1)
                {
                    DeleteRecords(record.Type);
                }
                else
                {
                    DnsResourceRecord[] newRecords = new DnsResourceRecord[existingRecords.Length - 1];

                    for (int i = 0, j = 0; i < existingRecords.Length; i++)
                    {
                        if (existingRecords[i] != null)
                            newRecords[j++] = existingRecords[i];
                    }

                    _entries.AddOrUpdate(record.Type, newRecords, delegate (DnsResourceRecordType key, DnsResourceRecord[] oldValue)
                    {
                        return newRecords;
                    });
                }
            }
        }

        private void DeleteRecords(DnsResourceRecordType type)
        {
            _entries.TryRemove(type, out _);

            DeleteEmptyParentZones(this);
        }

        private DnsResourceRecord[] FilterExpiredDisabledRecords(DnsResourceRecord[] records, bool serveStale)
        {
            if (records.Length == 1)
            {
                if (_authoritativeZone)
                {
                    DnsResourceRecordInfo rrInfo = records[0].Tag as DnsResourceRecordInfo;
                    if ((rrInfo != null) && rrInfo.Disabled)
                        return null;
                }
                else
                {
                    if (!serveStale && records[0].IsStale)
                        return null;

                    if (records[0].TtlValue < 1u)
                        return null; //ttl expired
                }

                return records;
            }

            List<DnsResourceRecord> newRecords = new List<DnsResourceRecord>(records.Length);

            foreach (DnsResourceRecord record in records)
            {
                if (_authoritativeZone)
                {
                    DnsResourceRecordInfo rrInfo = record.Tag as DnsResourceRecordInfo;
                    if ((rrInfo != null) && rrInfo.Disabled)
                        continue;
                }
                else
                {
                    if (!serveStale && record.IsStale)
                        continue;

                    if (record.TtlValue < 1u)
                        continue; //ttl expired
                }

                newRecords.Add(record);
            }

            if (newRecords.Count > 0)
                return newRecords.ToArray();

            return null;
        }

        private static Zone QueryFindClosestZone(Zone rootZone, string domain)
        {
            Zone currentZone = rootZone;

            string[] path = ConvertDomainToPath(domain);

            for (int i = 0; i < path.Length; i++)
            {
                string nextZoneLabel = path[i];

                if (currentZone._zones.TryGetValue(nextZoneLabel, out Zone nextZone))
                    currentZone = nextZone;
                else if (currentZone._zones.TryGetValue("*", out Zone nextWildcardZone))
                    currentZone = nextWildcardZone;
                else
                    return currentZone;
            }

            return currentZone;
        }

        private DnsResourceRecord[] QueryClosestCachedNameServers(bool serveStale)
        {
            Zone currentZone = this;
            DnsResourceRecord[] nsRecords;

            while (currentZone != null)
            {
                nsRecords = currentZone.QueryRecords(DnsResourceRecordType.NS, true, serveStale);
                if ((nsRecords != null) && (nsRecords.Length > 0) && (nsRecords[0].RDATA is DnsNSRecord))
                    return nsRecords;

                currentZone = currentZone._parentZone;
            }

            return null;
        }

        private DnsResourceRecord[] QueryClosestEnabledAuthority(string rootZoneServerDomain)
        {
            Zone currentZone = this;
            DnsResourceRecord[] nsRecords;

            while (currentZone != null)
            {
                if (currentZone._disabled)
                    return null;

                nsRecords = currentZone.QueryRecords(DnsResourceRecordType.SOA, true, false);
                if ((nsRecords != null) && (nsRecords.Length > 0) && (nsRecords[0].RDATA as DnsSOARecord).MasterNameServer.Equals(rootZoneServerDomain, StringComparison.OrdinalIgnoreCase))
                    return nsRecords;

                nsRecords = currentZone.QueryRecords(DnsResourceRecordType.NS, true, false);
                if ((nsRecords != null) && (nsRecords.Length > 0))
                    return nsRecords;

                currentZone = currentZone._parentZone;
            }

            return null;
        }

        private DnsResourceRecord[] QueryClosestAuthoritativeNameServers()
        {
            Zone currentZone = this;
            DnsResourceRecord[] nsRecords;

            while (currentZone != null)
            {
                if (currentZone._entries.ContainsKey(DnsResourceRecordType.SOA))
                {
                    nsRecords = currentZone.QueryRecords(DnsResourceRecordType.NS, true, false);
                    if ((nsRecords != null) && (nsRecords.Length > 0))
                        return nsRecords;

                    return null;
                }

                currentZone = currentZone._parentZone;
            }

            return null;
        }

        private static DnsResourceRecord[] QueryGlueRecords(Zone rootZone, DnsResourceRecord[] referenceRecords, bool serveStale)
        {
            List<DnsResourceRecord> glueRecords = new List<DnsResourceRecord>();

            foreach (DnsResourceRecord record in referenceRecords)
            {
                string glueDomain;

                switch (record.Type)
                {
                    case DnsResourceRecordType.NS:
                        glueDomain = (record.RDATA as DnsNSRecord).NSDomainName;
                        break;

                    case DnsResourceRecordType.MX:
                        glueDomain = (record.RDATA as DnsMXRecord).Exchange;
                        break;

                    default:
                        continue;
                }

                Zone zone = GetZone(rootZone, glueDomain, false);
                if ((zone != null) && !zone._disabled)
                {
                    {
                        DnsResourceRecord[] records = zone.QueryRecords(DnsResourceRecordType.A, true, serveStale);
                        if ((records != null) && (records.Length > 0) && (records[0].RDATA is DnsARecord))
                            glueRecords.AddRange(records);
                    }

                    {
                        DnsResourceRecord[] records = zone.QueryRecords(DnsResourceRecordType.AAAA, true, serveStale);
                        if ((records != null) && (records.Length > 0) && (records[0].RDATA is DnsAAAARecord))
                            glueRecords.AddRange(records);
                    }
                }
            }

            return glueRecords.ToArray();
        }

        private static DnsDatagram QueryAuthoritative(Zone rootZone, DnsDatagram request)
        {
            DnsQuestionRecord question = request.Question[0];
            string domain = question.Name.ToLower();

            Zone closestZone = QueryFindClosestZone(rootZone, domain);

            if (closestZone._disabled)
                return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, false, false, request.Header.RecursionDesired, false, false, false, DnsResponseCode.Refused, 1, 0, 0, 0), request.Question, new DnsResourceRecord[] { }, new DnsResourceRecord[] { }, new DnsResourceRecord[] { });

            DnsResourceRecord[] closestAuthority = closestZone.QueryClosestEnabledAuthority(rootZone._serverDomain);

            if (closestAuthority == null)
                return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, false, false, request.Header.RecursionDesired, false, false, false, DnsResponseCode.Refused, 1, 0, 0, 0), request.Question, new DnsResourceRecord[] { }, new DnsResourceRecord[] { }, new DnsResourceRecord[] { });

            if (closestAuthority[0].Type == DnsResourceRecordType.SOA)
            {
                //zone is hosted on this server
                if (DomainEquals(closestZone._zoneName, domain))
                {
                    //zone found
                    DnsResourceRecord[] answerRecords = closestZone.QueryRecords(question.Type, false, false);
                    if (answerRecords == null)
                    {
                        //record type not found
                        return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, true, false, request.Header.RecursionDesired, false, false, false, DnsResponseCode.NoError, 1, 0, (ushort)closestAuthority.Length, 0), request.Question, new DnsResourceRecord[] { }, closestAuthority, new DnsResourceRecord[] { });
                    }
                    else
                    {
                        //record type found
                        if (closestZone._zoneName.Contains("*"))
                        {
                            DnsResourceRecord[] wildcardAnswerRecords = new DnsResourceRecord[answerRecords.Length];

                            for (int i = 0; i < answerRecords.Length; i++)
                            {
                                DnsResourceRecord record = answerRecords[i];
                                wildcardAnswerRecords[i] = new DnsResourceRecord(domain, record.Type, record.Class, record.TtlValue, record.RDATA);
                            }

                            answerRecords = wildcardAnswerRecords;
                        }

                        DnsResourceRecord[] closestAuthoritativeNameServers;
                        DnsResourceRecord[] additional;

                        switch (question.Type)
                        {
                            case DnsResourceRecordType.NS:
                            case DnsResourceRecordType.MX:
                                closestAuthoritativeNameServers = new DnsResourceRecord[] { };
                                additional = QueryGlueRecords(rootZone, answerRecords, false);
                                break;

                            case DnsResourceRecordType.ANY:
                                closestAuthoritativeNameServers = new DnsResourceRecord[] { };
                                additional = new DnsResourceRecord[] { };
                                break;

                            default:
                                closestAuthoritativeNameServers = closestZone.QueryClosestAuthoritativeNameServers();

                                if (closestAuthoritativeNameServers == null)
                                {
                                    closestAuthoritativeNameServers = new DnsResourceRecord[] { };
                                    additional = new DnsResourceRecord[] { };
                                }
                                else
                                {
                                    additional = QueryGlueRecords(rootZone, closestAuthoritativeNameServers, false);
                                }

                                break;
                        }

                        return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, true, false, request.Header.RecursionDesired, false, false, false, DnsResponseCode.NoError, 1, (ushort)answerRecords.Length, (ushort)closestAuthoritativeNameServers.Length, (ushort)additional.Length), request.Question, answerRecords, closestAuthoritativeNameServers, additional);
                    }
                }
                else
                {
                    //zone doesnt exists
                    return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, true, false, request.Header.RecursionDesired, false, false, false, DnsResponseCode.NameError, 1, 0, (ushort)closestAuthority.Length, 0), request.Question, new DnsResourceRecord[] { }, closestAuthority, new DnsResourceRecord[] { });
                }
            }
            else
            {
                //zone is delegated
                DnsResourceRecord[] additional = QueryGlueRecords(rootZone, closestAuthority, false);

                return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, false, false, request.Header.RecursionDesired, false, false, false, DnsResponseCode.NoError, 1, 0, (ushort)closestAuthority.Length, (ushort)additional.Length), request.Question, new DnsResourceRecord[] { }, closestAuthority, additional);
            }
        }

        private static DnsDatagram QueryCache(Zone rootZone, DnsDatagram request, bool serveStale)
        {
            DnsQuestionRecord question = request.Question[0];
            string domain = question.Name.ToLower();

            Zone closestZone = QueryFindClosestZone(rootZone, domain);

            if (closestZone._zoneName.Equals(domain))
            {
                DnsResourceRecord[] answerRecords = closestZone.QueryRecords(question.Type, false, serveStale);
                if (answerRecords != null)
                {
                    if (answerRecords[0].RDATA is DnsEmptyRecord)
                    {
                        DnsResourceRecord[] responseAuthority;
                        DnsResourceRecord authority = (answerRecords[0].RDATA as DnsEmptyRecord).Authority;

                        if (authority == null)
                            responseAuthority = new DnsResourceRecord[] { };
                        else
                            responseAuthority = new DnsResourceRecord[] { authority };

                        return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, false, false, request.Header.RecursionDesired, true, false, false, DnsResponseCode.NoError, 1, 0, 1, 0), request.Question, new DnsResourceRecord[] { }, responseAuthority, new DnsResourceRecord[] { });
                    }

                    if (answerRecords[0].RDATA is DnsNXRecord)
                        return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, false, false, request.Header.RecursionDesired, true, false, false, DnsResponseCode.NameError, 1, 0, 1, 0), request.Question, new DnsResourceRecord[] { }, new DnsResourceRecord[] { (answerRecords[0].RDATA as DnsNXRecord).Authority }, new DnsResourceRecord[] { });

                    if (answerRecords[0].RDATA is DnsANYRecord)
                    {
                        DnsANYRecord anyRR = answerRecords[0].RDATA as DnsANYRecord;
                        return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, false, false, request.Header.RecursionDesired, true, false, false, DnsResponseCode.NoError, 1, (ushort)anyRR.Records.Length, 0, 0), request.Question, anyRR.Records, new DnsResourceRecord[] { }, new DnsResourceRecord[] { });
                    }

                    DnsResourceRecord[] additional;

                    switch (question.Type)
                    {
                        case DnsResourceRecordType.NS:
                        case DnsResourceRecordType.MX:
                            additional = QueryGlueRecords(rootZone, answerRecords, serveStale);
                            break;

                        default:
                            additional = new DnsResourceRecord[] { };
                            break;
                    }

                    return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, false, false, request.Header.RecursionDesired, true, false, false, DnsResponseCode.NoError, 1, (ushort)answerRecords.Length, 0, (ushort)additional.Length), request.Question, answerRecords, new DnsResourceRecord[] { }, additional);
                }
            }

            DnsResourceRecord[] nameServers = closestZone.QueryClosestCachedNameServers(serveStale);
            if (nameServers != null)
            {
                DnsResourceRecord[] additional = QueryGlueRecords(rootZone, nameServers, serveStale);

                return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, false, false, request.Header.RecursionDesired, true, false, false, DnsResponseCode.NoError, 1, 0, (ushort)nameServers.Length, (ushort)additional.Length), request.Question, new DnsResourceRecord[] { }, nameServers, additional);
            }

            return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, false, false, request.Header.RecursionDesired, true, false, false, DnsResponseCode.Refused, 1, 0, 0, 0), request.Question, new DnsResourceRecord[] { }, new DnsResourceRecord[] { }, new DnsResourceRecord[] { });
        }

        private static DnsDatagram QueryCacheGetClosestNameServers(Zone rootZone, DnsDatagram request, bool serveStale)
        {
            DnsQuestionRecord question = request.Question[0];
            string domain = question.Name.ToLower();

            Zone closestZone = QueryFindClosestZone(rootZone, domain);

            DnsResourceRecord[] nameServers = closestZone.QueryClosestCachedNameServers(serveStale);
            if (nameServers != null)
            {
                DnsResourceRecord[] additional = QueryGlueRecords(rootZone, nameServers, serveStale);

                return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, false, false, request.Header.RecursionDesired, true, false, false, DnsResponseCode.NoError, 1, 0, (ushort)nameServers.Length, (ushort)additional.Length), request.Question, new DnsResourceRecord[] { }, nameServers, additional);
            }

            return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, false, false, request.Header.RecursionDesired, true, false, false, DnsResponseCode.Refused, 1, 0, 0, 0), request.Question, new DnsResourceRecord[] { }, new DnsResourceRecord[] { }, new DnsResourceRecord[] { });
        }

        #endregion

        #region internal

        internal static bool DomainEquals(string domain1, string domain2)
        {
            string[] path1 = ConvertDomainToPath(domain1);
            string[] path2 = ConvertDomainToPath(domain2);

            int maxLen;
            int minLen;

            if (path1.Length > path2.Length)
            {
                maxLen = path1.Length;
                minLen = path2.Length;
            }
            else
            {
                maxLen = path2.Length;
                minLen = path1.Length;
            }

            for (int i = 0; i < maxLen; i++)
            {
                if (i == minLen)
                    return false;

                if ((path1[i] == "*") || (path2[i] == "*"))
                    return true;

                if (path1[i] != path2[i])
                    return false;
            }

            return true;
        }

        internal static Dictionary<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> GroupRecords(ICollection<DnsResourceRecord> records)
        {
            Dictionary<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> groupedByDomainRecords = new Dictionary<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>>();

            foreach (DnsResourceRecord record in records)
            {
                Dictionary<DnsResourceRecordType, List<DnsResourceRecord>> groupedByTypeRecords;
                string recordName = record.Name.ToLower();

                if (groupedByDomainRecords.ContainsKey(recordName))
                {
                    groupedByTypeRecords = groupedByDomainRecords[recordName];
                }
                else
                {
                    groupedByTypeRecords = new Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>();
                    groupedByDomainRecords.Add(recordName, groupedByTypeRecords);
                }

                List<DnsResourceRecord> groupedRecords;

                if (groupedByTypeRecords.ContainsKey(record.Type))
                {
                    groupedRecords = groupedByTypeRecords[record.Type];
                }
                else
                {
                    groupedRecords = new List<DnsResourceRecord>();
                    groupedByTypeRecords.Add(record.Type, groupedRecords);
                }

                groupedRecords.Add(record);
            }

            return groupedByDomainRecords;
        }

        internal DnsDatagram Query(DnsDatagram request, bool serveStale = false)
        {
            if (_authoritativeZone)
                return QueryAuthoritative(this, request);

            return QueryCache(this, request, serveStale);
        }

        internal void CacheResponse(DnsDatagram response)
        {
            if (_authoritativeZone)
                throw new InvalidOperationException("Cannot cache response into authoritative zone.");

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
                            authority.SetExpiry(MINIMUM_RECORD_TTL, _serveStaleTtl);

                            foreach (DnsQuestionRecord question in response.Question)
                            {
                                uint ttl = DEFAULT_RECORD_TTL;

                                if (authority.TtlValue < ttl)
                                    ttl = authority.TtlValue;

                                DnsResourceRecord record = new DnsResourceRecord(question.Name, question.Type, DnsClass.IN, ttl, new DnsNXRecord(authority));
                                record.SetExpiry(MINIMUM_RECORD_TTL, _serveStaleTtl);

                                CreateZone(this, question.Name).SetRecords(question.Type, new DnsResourceRecord[] { record });
                            }
                        }
                    }
                    break;

                case DnsResponseCode.NoError:
                    if (response.Answer.Length > 0)
                    {
                        foreach (DnsQuestionRecord question in response.Question)
                        {
                            string qName = question.Name;

                            foreach (DnsResourceRecord answer in response.Answer)
                            {
                                if (answer.Name.Equals(qName, StringComparison.OrdinalIgnoreCase))
                                {
                                    allRecords.Add(answer);

                                    switch (answer.Type)
                                    {
                                        case DnsResourceRecordType.CNAME:
                                            qName = (answer.RDATA as DnsCNAMERecord).CNAMEDomainName;
                                            break;

                                        case DnsResourceRecordType.NS:
                                            string nsDomain = (answer.RDATA as DnsNSRecord).NSDomainName;

                                            if (!nsDomain.EndsWith(".root-servers.net", StringComparison.OrdinalIgnoreCase))
                                            {
                                                foreach (DnsResourceRecord record in response.Additional)
                                                {
                                                    if (nsDomain.Equals(record.Name, StringComparison.OrdinalIgnoreCase))
                                                        allRecords.Add(record);
                                                }
                                            }

                                            break;

                                        case DnsResourceRecordType.MX:
                                            string mxExchange = (answer.RDATA as DnsMXRecord).Exchange;

                                            foreach (DnsResourceRecord record in response.Additional)
                                            {
                                                if (mxExchange.Equals(record.Name, StringComparison.OrdinalIgnoreCase))
                                                    allRecords.Add(record);
                                            }

                                            break;
                                    }
                                }
                            }
                        }
                    }
                    else if (response.Authority.Length > 0)
                    {
                        DnsResourceRecord authority = response.Authority[0];
                        if (authority.Type == DnsResourceRecordType.SOA)
                        {
                            authority.SetExpiry(MINIMUM_RECORD_TTL, _serveStaleTtl);

                            //empty response with authority
                            foreach (DnsQuestionRecord question in response.Question)
                            {
                                uint ttl = DEFAULT_RECORD_TTL;

                                if (authority.TtlValue < ttl)
                                    ttl = authority.TtlValue;

                                DnsResourceRecord record = new DnsResourceRecord(question.Name, question.Type, DnsClass.IN, ttl, new DnsEmptyRecord(authority));
                                record.SetExpiry(MINIMUM_RECORD_TTL, _serveStaleTtl);

                                CreateZone(this, question.Name).SetRecords(question.Type, new DnsResourceRecord[] { record });
                            }
                        }
                        else
                        {
                            foreach (DnsQuestionRecord question in response.Question)
                            {
                                foreach (DnsResourceRecord authorityRecord in response.Authority)
                                {
                                    if ((authorityRecord.Type == DnsResourceRecordType.NS) && question.Name.Equals(authorityRecord.Name, StringComparison.OrdinalIgnoreCase) && (authorityRecord.RDATA as DnsNSRecord).NSDomainName.Equals(response.Metadata.NameServerAddress.Host, StringComparison.OrdinalIgnoreCase))
                                    {
                                        //empty response from authority name server
                                        DnsResourceRecord record = new DnsResourceRecord(question.Name, question.Type, DnsClass.IN, DEFAULT_RECORD_TTL, new DnsEmptyRecord(null));
                                        record.SetExpiry(MINIMUM_RECORD_TTL, _serveStaleTtl);

                                        CreateZone(this, question.Name).SetRecords(question.Type, new DnsResourceRecord[] { record });
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    else
                    {
                        //empty response with no authority
                        foreach (DnsQuestionRecord question in response.Question)
                        {
                            DnsResourceRecord record = new DnsResourceRecord(question.Name, question.Type, DnsClass.IN, DEFAULT_RECORD_TTL, new DnsEmptyRecord(null));
                            record.SetExpiry(MINIMUM_RECORD_TTL, _serveStaleTtl);

                            CreateZone(this, question.Name).SetRecords(question.Type, new DnsResourceRecord[] { record });
                        }
                    }

                    break;

                default:
                    return; //nothing to do
            }

            if ((response.Question.Length > 0) && ((response.Question[0].Type != DnsResourceRecordType.NS) || (response.Answer.Length == 0)))
            {
                foreach (DnsQuestionRecord question in response.Question)
                {
                    foreach (DnsResourceRecord authority in response.Authority)
                    {
                        if (question.Name.Equals(authority.Name, StringComparison.OrdinalIgnoreCase) || question.Name.EndsWith("." + authority.Name, StringComparison.OrdinalIgnoreCase))
                        {
                            allRecords.Add(authority);

                            if (authority.Type == DnsResourceRecordType.NS)
                            {
                                string nsDomain = (authority.RDATA as DnsNSRecord).NSDomainName;

                                if (!nsDomain.EndsWith(".root-servers.net", StringComparison.OrdinalIgnoreCase))
                                {
                                    foreach (DnsResourceRecord record in response.Additional)
                                    {
                                        if (nsDomain.Equals(record.Name, StringComparison.OrdinalIgnoreCase))
                                            allRecords.Add(record);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            //set expiry for cached records
            foreach (DnsResourceRecord record in allRecords)
                record.SetExpiry(MINIMUM_RECORD_TTL, _serveStaleTtl);

            SetRecords(allRecords);

            //cache for ANY request
            if ((response.Question.Length > 0) && (response.Question[0].Type == DnsResourceRecordType.ANY) && (response.Answer.Length > 0))
            {
                uint ttl = DEFAULT_RECORD_TTL;

                foreach (DnsResourceRecord answer in response.Answer)
                {
                    if (answer.TtlValue < ttl)
                        ttl = answer.TtlValue;
                }

                DnsResourceRecord anyRR = new DnsResourceRecord(response.Question[0].Name, DnsResourceRecordType.ANY, DnsClass.IN, ttl, new DnsANYRecord(response.Answer));
                anyRR.SetExpiry(MINIMUM_RECORD_TTL, _serveStaleTtl);

                CreateZone(this, response.Question[0].Name).SetRecords(DnsResourceRecordType.ANY, new DnsResourceRecord[] { anyRR });
            }
        }

        internal DnsDatagram QueryCacheGetClosestNameServers(DnsDatagram request, bool serveStale = false)
        {
            if (_authoritativeZone)
                throw new InvalidOperationException("Cannot query authoritative zone for closest cached name servers.");

            return QueryCacheGetClosestNameServers(this, request, serveStale);
        }

        internal void RemoveExpiredCachedRecords()
        {
            if (_authoritativeZone)
                throw new InvalidOperationException("Cannot remove cached records from authoritative zone.");

            RemoveExpiredCachedRecords(this);
        }

        #endregion

        #region public

        public void SetRecords(string domain, DnsResourceRecordType type, uint ttl, DnsResourceRecordData[] records)
        {
            DnsResourceRecord[] resourceRecords = new DnsResourceRecord[records.Length];

            for (int i = 0; i < records.Length; i++)
                resourceRecords[i] = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, records[i]);

            CreateZone(this, domain).SetRecords(type, resourceRecords);
        }

        public void SetRecords(ICollection<DnsResourceRecord> records)
        {
            Dictionary<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> groupedByDomainRecords = GroupRecords(records);

            //add grouped records
            foreach (KeyValuePair<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> groupedByTypeRecords in groupedByDomainRecords)
            {
                string domain = groupedByTypeRecords.Key;
                Zone zone = CreateZone(this, domain);

                foreach (KeyValuePair<DnsResourceRecordType, List<DnsResourceRecord>> groupedRecords in groupedByTypeRecords.Value)
                {
                    DnsResourceRecordType type = groupedRecords.Key;
                    DnsResourceRecord[] resourceRecords = groupedRecords.Value.ToArray();

                    zone.SetRecords(type, resourceRecords);
                }
            }
        }

        public void AddRecord(string domain, DnsResourceRecordType type, uint ttl, DnsResourceRecordData record)
        {
            DnsResourceRecord rr = new DnsResourceRecord(domain, type, DnsClass.IN, ttl, record);
            CreateZone(this, domain).AddRecord(rr);
        }

        public void UpdateRecord(DnsResourceRecord oldRecord, DnsResourceRecord newRecord)
        {
            if (oldRecord.Type != newRecord.Type)
                throw new DnsServerException("Cannot update record: new record must be of same type.");

            if (oldRecord.Type == DnsResourceRecordType.SOA)
                throw new DnsServerException("Cannot update record: use SetRecords() for updating SOA record.");

            Zone currentZone = GetZone(this, oldRecord.Name, false);
            if (currentZone == null)
                throw new DnsServerException("Cannot update record: old record does not exists.");

            switch (oldRecord.Type)
            {
                case DnsResourceRecordType.CNAME:
                case DnsResourceRecordType.PTR:
                    if (oldRecord.Name.Equals(newRecord.Name, StringComparison.OrdinalIgnoreCase))
                    {
                        currentZone.SetRecords(newRecord.Type, new DnsResourceRecord[] { newRecord });
                    }
                    else
                    {
                        currentZone.DeleteRecords(oldRecord.Type);
                        CreateZone(this, newRecord.Name).SetRecords(newRecord.Type, new DnsResourceRecord[] { newRecord });
                    }
                    break;

                default:
                    currentZone.DeleteRecord(oldRecord);
                    CreateZone(this, newRecord.Name).AddRecord(newRecord); //create zone since delete record will also delete empty sub zones
                    break;
            }
        }

        public void DeleteRecord(string domain, DnsResourceRecordType type, DnsResourceRecordData record)
        {
            Zone currentZone = GetZone(this, domain, false);
            if (currentZone != null)
                currentZone.DeleteRecord(new DnsResourceRecord(domain, type, DnsClass.IN, 0, record));
        }

        public void DeleteRecords(string domain, DnsResourceRecordType type)
        {
            Zone currentZone = GetZone(this, domain, false);
            if (currentZone != null)
                currentZone.DeleteRecords(type);
        }

        public DnsResourceRecord[] GetAllRecords(string domain = "", DnsResourceRecordType type = DnsResourceRecordType.ANY, bool includeSubDomains = true, bool authoritative = false)
        {
            Zone currentZone = GetZone(this, domain, authoritative);
            if (currentZone == null)
                return new DnsResourceRecord[] { };

            DnsResourceRecord[] records = currentZone.GetAllRecords(type, includeSubDomains);
            if (records != null)
                return records;

            return new DnsResourceRecord[] { };
        }

        public string[] ListSubZones(string domain = "")
        {
            Zone currentZone = GetZone(this, domain, false);
            if (currentZone == null)
                return new string[] { }; //no zone for given domain

            string[] subZoneNames = new string[currentZone._zones.Keys.Count];
            currentZone._zones.Keys.CopyTo(subZoneNames, 0);

            return subZoneNames;
        }

        public ICollection<ZoneInfo> ListAuthoritativeZones(string domain = "")
        {
            Zone currentZone = GetZone(this, domain, false);
            if (currentZone == null)
                return new ZoneInfo[] { }; //no zone for given domain

            List<Zone> zones = new List<Zone>();
            currentZone.ListAuthoritativeZones(zones);

            List<ZoneInfo> zoneNames = new List<ZoneInfo>();

            foreach (Zone zone in zones)
                zoneNames.Add(new ZoneInfo(zone));

            return zoneNames;
        }

        public bool DeleteZone(string domain, bool deleteSubZones)
        {
            return DeleteZone(this, domain, deleteSubZones);
        }

        public void DisableZone(string domain)
        {
            Zone currentZone = GetZone(this, domain, false);
            if (currentZone != null)
                currentZone._disabled = true;
        }

        public void EnableZone(string domain)
        {
            Zone currentZone = GetZone(this, domain, false);
            if (currentZone != null)
                currentZone._disabled = false;
        }

        public bool IsZoneDisabled(string domain)
        {
            Zone currentZone = GetZone(this, domain, false);
            if (currentZone != null)
                return currentZone._disabled;

            return false;
        }

        public bool ZoneExists(string domain)
        {
            Zone currentZone = GetZone(this, domain, false);
            return (currentZone != null);
        }

        public bool ZoneExistsAndEnabled(string domain)
        {
            Zone currentZone = GetZone(this, domain, false);
            return (currentZone != null) && !currentZone._disabled;
        }

        public void Flush()
        {
            _zones.Clear();
            _entries.Clear();

            if (!_authoritativeZone)
                LoadRootHintsInCache();
        }

        #endregion

        #region properties

        public bool IsAuthoritative
        { get { return _authoritativeZone; } }

        public string ServerDomain
        {
            get { return _serverDomain; }
            set { _serverDomain = value; }
        }

        public uint ServeStaleTtl
        {
            get { return _serveStaleTtl; }
            set { _serveStaleTtl = value; }
        }

        #endregion

        public class ZoneInfo : IComparable<ZoneInfo>
        {
            #region variables

            readonly string _zoneName;
            readonly bool _disabled;

            #endregion

            #region constructor

            public ZoneInfo(string zoneName, bool disabled)
            {
                _zoneName = zoneName;
                _disabled = disabled;
            }

            public ZoneInfo(Zone zone)
            {
                _zoneName = zone._zoneName;
                _disabled = zone._disabled;
            }

            #endregion

            #region public

            public int CompareTo(ZoneInfo other)
            {
                return this._zoneName.CompareTo(other._zoneName);
            }

            #endregion

            #region properties

            public string ZoneName
            { get { return _zoneName; } }

            public bool Disabled
            { get { return _disabled; } }

            #endregion
        }

        public class DnsResourceRecordInfo
        {
            #region variables

            readonly bool _disabled;

            #endregion

            #region constructor

            public DnsResourceRecordInfo()
            { }

            public DnsResourceRecordInfo(bool disabled)
            {
                _disabled = disabled;
            }

            public DnsResourceRecordInfo(BinaryReader bR)
            {
                switch (bR.ReadByte()) //version
                {
                    case 1:
                        _disabled = bR.ReadBoolean();
                        break;

                    default:
                        throw new NotSupportedException("Zone.DnsResourceRecordInfo format version not supported.");
                }
            }

            #endregion

            #region public

            public void WriteTo(BinaryWriter bW)
            {
                bW.Write((byte)1); //version
                bW.Write(_disabled);
            }

            #endregion

            #region properties

            public bool Disabled
            { get { return _disabled; } }

            #endregion
        }

        class DnsNXRecord : DnsResourceRecordData
        {
            #region variables

            readonly DnsResourceRecord _authority;

            #endregion

            #region constructor

            public DnsNXRecord(DnsResourceRecord authority)
            {
                _authority = authority;
            }

            #endregion

            #region protected

            protected override void Parse(Stream s)
            { }

            protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries)
            { }

            #endregion

            #region public

            public override bool Equals(object obj)
            {
                if (ReferenceEquals(null, obj))
                    return false;

                if (ReferenceEquals(this, obj))
                    return true;

                DnsNXRecord other = obj as DnsNXRecord;
                if (other == null)
                    return false;

                return _authority.Equals(other._authority);
            }

            public override int GetHashCode()
            {
                return _authority.GetHashCode();
            }

            public override string ToString()
            {
                return _authority.RDATA.ToString();
            }

            #endregion

            #region properties

            public DnsResourceRecord Authority
            { get { return _authority; } }

            #endregion
        }

        class DnsEmptyRecord : DnsResourceRecordData
        {
            #region variables

            readonly DnsResourceRecord _authority;

            #endregion

            #region constructor

            public DnsEmptyRecord(DnsResourceRecord authority)
            {
                _authority = authority;
            }

            #endregion

            #region protected

            protected override void Parse(Stream s)
            { }

            protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries)
            { }

            #endregion

            #region public

            public override bool Equals(object obj)
            {
                if (ReferenceEquals(null, obj))
                    return false;

                if (ReferenceEquals(this, obj))
                    return true;

                DnsEmptyRecord other = obj as DnsEmptyRecord;
                if (other == null)
                    return false;

                return _authority.Equals(other._authority);
            }

            public override int GetHashCode()
            {
                return _authority.GetHashCode();
            }

            public override string ToString()
            {
                return _authority.RDATA.ToString();
            }

            #endregion

            #region properties

            public DnsResourceRecord Authority
            { get { return _authority; } }

            #endregion
        }

        class DnsANYRecord : DnsResourceRecordData
        {
            #region variables

            readonly DnsResourceRecord[] _records;

            #endregion

            #region constructor

            public DnsANYRecord(DnsResourceRecord[] records)
            {
                _records = records;
            }

            #endregion

            #region protected

            protected override void Parse(Stream s)
            { }

            protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries)
            { }

            public override string ToString()
            {
                return "[MultipleRecords: " + _records.Length + "]";
            }

            #endregion

            #region public

            public override bool Equals(object obj)
            {
                if (ReferenceEquals(null, obj))
                    return false;

                if (ReferenceEquals(this, obj))
                    return true;

                DnsANYRecord other = obj as DnsANYRecord;
                if (other == null)
                    return false;

                return true;
            }

            public override int GetHashCode()
            {
                return 0;
            }

            #endregion

            #region properties

            public DnsResourceRecord[] Records
            { get { return _records; } }

            #endregion
        }
    }
}
