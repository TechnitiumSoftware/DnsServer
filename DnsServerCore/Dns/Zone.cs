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
using System.Collections.Concurrent;
using System.Collections.Generic;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns
{
    public enum ZoneType
    {
        Cache = 0,
        Primary = 1,
        Secondary = 2,
        Stub = 3
    }

    public class Zone
    {
        #region variables

        readonly ZoneType zoneType;
        readonly bool _authoritativeZone;

        readonly Zone _parentZone;
        readonly string _zoneLabel;
        readonly string _zoneName;

        bool _disabled;
        bool _internal;

        ConcurrentDictionary<string, Zone> _zones;
        ConcurrentDictionary<DnsResourceRecordType, DnsResourceRecord[]> _entries;

        string _serverDomain;

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

            if (!string.IsNullOrEmpty(_parentZone._zoneName))
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

                if (currentZone._zones == null)
                    currentZone._zones = new ConcurrentDictionary<string, Zone>(1, 5);

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

            if (authoritative && (currentZone._entries != null) && currentZone._entries.ContainsKey(DnsResourceRecordType.SOA))
                authoritativeZone = currentZone;

            string[] path = ConvertDomainToPath(domain);

            for (int i = 0; i < path.Length; i++)
            {
                string nextZoneLabel = path[i];

                if ((currentZone._zones != null) && currentZone._zones.TryGetValue(nextZoneLabel, out Zone nextZone))
                {
                    currentZone = nextZone;
                }
                else
                {
                    if (authoritative)
                        return authoritativeZone;

                    return null;
                }

                if (authoritative && (currentZone._entries != null) && currentZone._entries.ContainsKey(DnsResourceRecordType.SOA))
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

            currentZone._entries = null;

            DeleteSubZones(currentZone, deleteSubZones);
            DeleteEmptyParentZones(currentZone);

            return true;
        }

        private static bool DeleteSubZones(Zone currentZone, bool deleteSubZones)
        {
            if (currentZone._authoritativeZone)
            {
                if (!deleteSubZones && (currentZone._entries != null) && currentZone._entries.ContainsKey(DnsResourceRecordType.SOA))
                    return false; //this is a zone so return false
            }
            else
            {
                //cache zone
                if (currentZone._zoneName.Equals("root-servers.net", StringComparison.OrdinalIgnoreCase))
                    return false; //cannot delete root-servers.net
            }

            currentZone._entries = null;

            if (currentZone._zones == null)
                return true;

            List<Zone> subDomainsToDelete = new List<Zone>();

            foreach (KeyValuePair<string, Zone> zone in currentZone._zones)
            {
                if (DeleteSubZones(zone.Value, deleteSubZones))
                    subDomainsToDelete.Add(zone.Value);
            }

            foreach (Zone subDomain in subDomainsToDelete)
                currentZone._zones.TryRemove(subDomain._zoneLabel, out _);

            if (currentZone._zones.Count == 0)
            {
                currentZone._zones = null;
                return true;
            }

            return false;
        }

        private static void DeleteEmptyParentZones(Zone currentZone)
        {
            while (currentZone._parentZone != null)
            {
                if (((currentZone._entries != null) && (currentZone._entries.Count > 0)) || ((currentZone._zones != null) && (currentZone._zones.Count > 0)))
                    break;

                currentZone._parentZone._zones.TryRemove(currentZone._zoneLabel, out _);

                currentZone = currentZone._parentZone;
            }
        }

        private static void RemoveExpiredCachedRecords(Zone currentZone)
        {
            //remove expired entries in current zone
            if (currentZone._entries != null)
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
            if (currentZone._zones != null)
            {
                List<string> subZonesToRemove = null;

                foreach (KeyValuePair<string, Zone> zone in currentZone._zones)
                {
                    RemoveExpiredCachedRecords(zone.Value);

                    if (((zone.Value._zones == null) || (zone.Value._zones.Count == 0)) && ((zone.Value._entries == null) || (zone.Value._entries.Count == 0)))
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

                    if (currentZone._zones.Count == 0)
                        currentZone._zones = null;
                }
            }
        }

        private DnsResourceRecord[] QueryRecords(DnsResourceRecordType type, bool bypassCNAME, bool serveStale)
        {
            if (_disabled)
                return null;

            if (_authoritativeZone && (type == DnsResourceRecordType.ANY))
            {
                if (_entries == null)
                    return Array.Empty<DnsResourceRecord>();

                List<DnsResourceRecord> allRecords = new List<DnsResourceRecord>();

                foreach (KeyValuePair<DnsResourceRecordType, DnsResourceRecord[]> entry in _entries)
                    allRecords.AddRange(entry.Value);

                return FilterExpiredDisabledRecords(allRecords.ToArray(), serveStale);
            }

            if (!bypassCNAME && (_entries != null) && _entries.TryGetValue(DnsResourceRecordType.CNAME, out DnsResourceRecord[] existingCNAMERecords))
            {
                DnsResourceRecord[] records = FilterExpiredDisabledRecords(existingCNAMERecords, serveStale);
                if (records != null)
                    return records;
            }

            if ((_entries != null) && _entries.TryGetValue(type, out DnsResourceRecord[] existingRecords))
            {
                DnsResourceRecord[] records = FilterExpiredDisabledRecords(existingRecords, serveStale);

                if (records != null)
                    DnsClient.ShuffleArray(records); //shuffle records to allow load balancing

                return records;
            }

            return null;
        }

        private List<DnsResourceRecord> GetAllRecords(DnsResourceRecordType type, bool includeSubDomains)
        {
            List<DnsResourceRecord> allRecords = new List<DnsResourceRecord>();

            if (type == DnsResourceRecordType.ANY)
            {
                if (_entries != null)
                {
                    foreach (KeyValuePair<DnsResourceRecordType, DnsResourceRecord[]> entry in _entries)
                    {
                        if (entry.Key != DnsResourceRecordType.ANY)
                            allRecords.AddRange(entry.Value);
                    }
                }
            }
            else if (type == DnsResourceRecordType.AXFR)
            {
                includeSubDomains = true;

                if ((_entries == null) || !_entries.TryGetValue(DnsResourceRecordType.SOA, out DnsResourceRecord[] soaRecord))
                    throw new DnsServerException("No SOA record found for AXFR in current zone.");

                allRecords.Add(soaRecord[0]);

                foreach (KeyValuePair<DnsResourceRecordType, DnsResourceRecord[]> entry in _entries)
                {
                    if (entry.Key != DnsResourceRecordType.SOA)
                        allRecords.AddRange(entry.Value);
                }
            }
            else if ((_entries != null) && _entries.TryGetValue(type, out DnsResourceRecord[] existingRecords))
            {
                allRecords.AddRange(existingRecords);
            }

            if (includeSubDomains && (_zones != null))
            {
                DnsResourceRecordType subType;

                if (type == DnsResourceRecordType.AXFR)
                    subType = DnsResourceRecordType.ANY;
                else
                    subType = type;

                foreach (KeyValuePair<string, Zone> zone in _zones)
                {
                    if ((zone.Value._entries != null) && !zone.Value._entries.ContainsKey(DnsResourceRecordType.SOA))
                        allRecords.AddRange(zone.Value.GetAllRecords(subType, true));
                }
            }

            if (type == DnsResourceRecordType.AXFR)
                allRecords.Add(allRecords[0]);

            return allRecords;
        }

        private void ListAuthoritativeZones(List<Zone> zones)
        {
            List<DnsResourceRecord> soa = GetAllRecords(DnsResourceRecordType.SOA, false);
            if ((soa.Count > 0) && (soa[0].RDATA is DnsSOARecord))
                zones.Add(this);

            if (_zones != null)
            {
                foreach (KeyValuePair<string, Zone> entry in _zones)
                    entry.Value.ListAuthoritativeZones(zones);
            }
        }

        private void SetRecords(DnsResourceRecordType type, DnsResourceRecord[] records)
        {
            if (!_authoritativeZone && (records.Length > 0) && (records[0].RDATA is DnsCache.DnsFailureRecord))
            {
                //call trying to cache failure record
                if ((_entries != null) && _entries.TryGetValue(type, out DnsResourceRecord[] existingRecords))
                {
                    if ((existingRecords.Length > 0) && !(existingRecords[0].RDATA is DnsCache.DnsFailureRecord))
                        return; //skip to avoid overwriting a useful stale record with a failure record to allow serve-stale to work as intended
                }
            }

            if (_authoritativeZone && (type == DnsResourceRecordType.CNAME) && (_entries != null) && _entries.ContainsKey(DnsResourceRecordType.SOA))
                throw new DnsServerException("Cannot add CNAME record to zone root.");

            if (_entries == null)
                _entries = new ConcurrentDictionary<DnsResourceRecordType, DnsResourceRecord[]>(1, 5);

            _entries.AddOrUpdate(type, records, delegate (DnsResourceRecordType key, DnsResourceRecord[] existingValues)
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
                        _entries.TryRemove(DnsResourceRecordType.CNAME, out _);
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

            if (_entries == null)
                _entries = new ConcurrentDictionary<DnsResourceRecordType, DnsResourceRecord[]>(1, 5);

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
            if ((_entries != null) && _entries.TryGetValue(record.Type, out DnsResourceRecord[] existingRecords))
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

            if (_entries.Count == 0)
                _entries = null;

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

            if (records.Length == newRecords.Count)
                return records;

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

                if (currentZone._zones == null)
                    return currentZone;

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

        private DnsResourceRecord[] QueryClosestAuthority(string rootZoneServerDomain)
        {
            Zone currentZone = this;
            DnsResourceRecord[] nsRecords;

            while (currentZone != null)
            {
                if (!currentZone._disabled)
                {
                    nsRecords = currentZone.QueryRecords(DnsResourceRecordType.SOA, true, false);
                    if ((nsRecords != null) && (nsRecords.Length > 0) && (nsRecords[0].RDATA as DnsSOARecord).MasterNameServer.Equals(rootZoneServerDomain, StringComparison.OrdinalIgnoreCase))
                        return nsRecords;

                    nsRecords = currentZone.QueryRecords(DnsResourceRecordType.NS, true, false);
                    if ((nsRecords != null) && (nsRecords.Length > 0))
                        return nsRecords;
                }

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
                if ((_entries != null) && currentZone._entries.ContainsKey(DnsResourceRecordType.SOA))
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
            DnsResourceRecord[] closestAuthority = closestZone.QueryClosestAuthority(rootZone._serverDomain);

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
                    if (answerRecords[0].RDATA is DnsCache.DnsEmptyRecord)
                    {
                        DnsResourceRecord[] responseAuthority;
                        DnsResourceRecord authority = (answerRecords[0].RDATA as DnsCache.DnsEmptyRecord).Authority;

                        if (authority == null)
                            responseAuthority = new DnsResourceRecord[] { };
                        else
                            responseAuthority = new DnsResourceRecord[] { authority };

                        return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, false, false, request.Header.RecursionDesired, true, false, false, DnsResponseCode.NoError, 1, 0, 1, 0), request.Question, new DnsResourceRecord[] { }, responseAuthority, new DnsResourceRecord[] { });
                    }

                    if (answerRecords[0].RDATA is DnsCache.DnsNXRecord)
                    {
                        DnsResourceRecord[] responseAuthority;
                        DnsResourceRecord authority = (answerRecords[0].RDATA as DnsCache.DnsNXRecord).Authority;

                        if (authority == null)
                            responseAuthority = new DnsResourceRecord[] { };
                        else
                            responseAuthority = new DnsResourceRecord[] { authority };

                        return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, false, false, request.Header.RecursionDesired, true, false, false, DnsResponseCode.NameError, 1, 0, 1, 0), request.Question, new DnsResourceRecord[] { }, responseAuthority, new DnsResourceRecord[] { });
                    }

                    if (answerRecords[0].RDATA is DnsCache.DnsANYRecord)
                    {
                        DnsCache.DnsANYRecord anyRR = answerRecords[0].RDATA as DnsCache.DnsANYRecord;
                        return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, false, false, request.Header.RecursionDesired, true, false, false, DnsResponseCode.NoError, 1, (ushort)anyRR.Records.Length, 0, 0), request.Question, anyRR.Records, new DnsResourceRecord[] { }, new DnsResourceRecord[] { });
                    }

                    if (answerRecords[0].RDATA is DnsCache.DnsFailureRecord)
                        return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, false, false, request.Header.RecursionDesired, true, false, false, (answerRecords[0].RDATA as DnsCache.DnsFailureRecord).RCODE, 1, 0, 0, 0), request.Question, new DnsResourceRecord[] { }, new DnsResourceRecord[] { }, new DnsResourceRecord[] { });

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

            while (closestZone != null)
            {
                DnsResourceRecord[] nameServers = closestZone.QueryClosestCachedNameServers(serveStale);
                if (nameServers == null)
                    break;

                DnsResourceRecord[] additional = QueryGlueRecords(rootZone, nameServers, serveStale);
                if (additional.Length > 0)
                    return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, false, false, request.Header.RecursionDesired, true, false, false, DnsResponseCode.NoError, 1, 0, (ushort)nameServers.Length, (ushort)additional.Length), request.Question, new DnsResourceRecord[] { }, nameServers, additional);

                closestZone = closestZone._parentZone;
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

        internal DnsDatagram Query(DnsDatagram request, bool serveStale = false)
        {
            if (_authoritativeZone)
                return QueryAuthoritative(this, request);

            return QueryCache(this, request, serveStale);
        }

        internal DnsDatagram QueryCacheGetClosestNameServers(DnsDatagram request, bool serveStale = false)
        {
            if (_authoritativeZone)
                throw new InvalidOperationException("Cannot query authoritative zone for closest cached name servers.");

            Zone closestZone = QueryFindClosestZone(this, request.Question[0].Name.ToLower());

            while (closestZone != null)
            {
                DnsResourceRecord[] nameServers = closestZone.QueryClosestCachedNameServers(serveStale);
                if (nameServers == null)
                    break;

                DnsResourceRecord[] additional = QueryGlueRecords(this, nameServers, serveStale);
                if (additional.Length > 0)
                    return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, false, false, request.Header.RecursionDesired, true, false, false, DnsResponseCode.NoError, 1, 0, (ushort)nameServers.Length, (ushort)additional.Length), request.Question, new DnsResourceRecord[] { }, nameServers, additional);

                closestZone = closestZone._parentZone;
            }

            return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, false, false, request.Header.RecursionDesired, true, false, false, DnsResponseCode.Refused, 1, 0, 0, 0), request.Question, new DnsResourceRecord[] { }, new DnsResourceRecord[] { }, new DnsResourceRecord[] { });
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

        public void SetRecords(ICollection<DnsResourceRecord> resourceRecords)
        {
            if (resourceRecords.Count == 1)
            {
                foreach (DnsResourceRecord resourceRecord in resourceRecords)
                    CreateZone(this, resourceRecord.Name).SetRecords(resourceRecord.Type, new DnsResourceRecord[] { resourceRecord });
            }
            else
            {
                Dictionary<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> groupedByDomainRecords = DnsResourceRecord.GroupRecords(resourceRecords);

                //add grouped records
                foreach (KeyValuePair<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> groupedByTypeRecords in groupedByDomainRecords)
                {
                    string domain = groupedByTypeRecords.Key;
                    Zone zone = CreateZone(this, domain);

                    foreach (KeyValuePair<DnsResourceRecordType, List<DnsResourceRecord>> groupedRecords in groupedByTypeRecords.Value)
                    {
                        DnsResourceRecordType type = groupedRecords.Key;
                        DnsResourceRecord[] records = groupedRecords.Value.ToArray();

                        zone.SetRecords(type, records);
                    }
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

        public List<DnsResourceRecord> GetAllRecords(string domain = "", DnsResourceRecordType type = DnsResourceRecordType.ANY, bool includeSubDomains = true, bool authoritative = false)
        {
            Zone currentZone = GetZone(this, domain, authoritative);
            if (currentZone == null)
                return new List<DnsResourceRecord>();

            return currentZone.GetAllRecords(type, includeSubDomains);
        }

        public string[] ListSubZones(string domain = "")
        {
            Zone currentZone = GetZone(this, domain, false);
            if (currentZone == null)
                return Array.Empty<string>(); //no zone for given domain

            if (currentZone._zones == null)
                return Array.Empty<string>(); //no sub zone for current zone

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
                zoneNames.Add(new ZoneInfo(zone._zoneName, zone._disabled, zone._internal));

            return zoneNames;
        }

        public ZoneInfo GetZoneInfo(string domain)
        {
            Zone currentZone = GetZone(this, domain, true);
            if (currentZone == null)
                return null;

            return new ZoneInfo(currentZone._zoneName, currentZone._disabled, currentZone._internal);
        }

        public void MakeZoneInternal(string domain)
        {
            Zone currentZone = GetZone(this, domain, true);
            if (currentZone != null)
                currentZone._internal = true;
        }

        public bool DeleteZone(string domain, bool deleteSubZones)
        {
            return DeleteZone(this, domain, deleteSubZones);
        }

        public void DisableZone(string domain)
        {
            Zone currentZone = GetZone(this, domain, true);
            if (currentZone != null)
                currentZone._disabled = true;
        }

        public void EnableZone(string domain)
        {
            Zone currentZone = GetZone(this, domain, true);
            if (currentZone != null)
                currentZone._disabled = false;
        }

        public bool IsZoneDisabled(string domain)
        {
            Zone currentZone = GetZone(this, domain, true);
            if (currentZone != null)
                return currentZone._disabled;

            return false;
        }

        public bool ZoneExists(string domain)
        {
            Zone currentZone = GetZone(this, domain, true);
            return (currentZone != null);
        }

        public bool ZoneExistsAndEnabled(string domain)
        {
            Zone currentZone = GetZone(this, domain, true);
            return (currentZone != null) && !currentZone._disabled;
        }

        public void Flush()
        {
            _zones = null;
            _entries = null;

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

        #endregion
    }
}
