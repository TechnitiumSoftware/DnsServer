/*
Technitium Library
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
using System.Collections.Generic;
using System.IO;
using System.Threading;
using TechnitiumLibrary.Net;

namespace DnsServerCore
{
    public class Zone
    {
        #region variables

        string _name;
        bool _authoritativeZone;

        Dictionary<string, Zone> _subZone = new Dictionary<string, Zone>();
        ReaderWriterLockSlim _subZoneLock = new ReaderWriterLockSlim();

        Dictionary<string, Dictionary<DnsResourceRecordType, DnsResourceRecord[]>> _zoneEntries = new Dictionary<string, Dictionary<DnsResourceRecordType, DnsResourceRecord[]>>();
        ReaderWriterLockSlim _zoneEntriesLock = new ReaderWriterLockSlim();

        #endregion

        #region constructor

        public Zone(bool authoritativeZone)
        {
            _name = "";
            _authoritativeZone = authoritativeZone;

            if (!_authoritativeZone)
                LoadRootHintsInCache();
        }

        private Zone(string name, bool authoritativeZone)
        {
            _name = name.ToLower();
            _authoritativeZone = authoritativeZone;
        }

        #endregion

        #region private

        private void LoadRootHintsInCache()
        {
            //load root server records
            DnsResourceRecordData[] nsRecords = new DnsResourceRecordData[DnsClient.ROOT_NAME_SERVERS_IPv4.Length];

            for (int i = 0; i < DnsClient.ROOT_NAME_SERVERS_IPv4.Length; i++)
            {
                NameServerAddress rootServer = DnsClient.ROOT_NAME_SERVERS_IPv4[i];

                nsRecords[i] = new DnsNSRecord(rootServer.Domain);
                SetRecord(rootServer.Domain, DnsResourceRecordType.A, 172800, new DnsResourceRecordData[] { new DnsARecord(rootServer.EndPoint.Address) });
            }

            for (int i = 0; i < DnsClient.ROOT_NAME_SERVERS_IPv6.Length; i++)
            {
                NameServerAddress rootServer = DnsClient.ROOT_NAME_SERVERS_IPv6[i];

                SetRecord(rootServer.Domain, DnsResourceRecordType.AAAA, 172800, new DnsResourceRecordData[] { new DnsAAAARecord(rootServer.EndPoint.Address) });
            }

            SetRecord("", DnsResourceRecordType.NS, 172800, nsRecords);
        }

        private static string[] ConvertDomainToPath(string domainName)
        {
            if (domainName == null)
                return new string[] { };

            string[] path = domainName.ToLower().Split('.');
            Array.Reverse(path);

            return path;
        }

        private void SetRecord(DnsResourceRecord[] resourceRecords)
        {
            if (resourceRecords.Length < 1)
                return;

            string domain = resourceRecords[0].Name;
            DnsResourceRecordType type = resourceRecords[0].Type;

            _zoneEntriesLock.EnterWriteLock();
            try
            {
                Dictionary<DnsResourceRecordType, DnsResourceRecord[]> zoneTypeEntries;

                if (_zoneEntries.ContainsKey(domain))
                {
                    zoneTypeEntries = _zoneEntries[domain];
                }
                else
                {
                    zoneTypeEntries = new Dictionary<DnsResourceRecordType, DnsResourceRecord[]>();
                    _zoneEntries.Add(domain, zoneTypeEntries);
                }

                if (zoneTypeEntries.ContainsKey(type))
                    zoneTypeEntries[type] = resourceRecords;
                else
                    zoneTypeEntries.Add(type, resourceRecords);
            }
            finally
            {
                _zoneEntriesLock.ExitWriteLock();
            }
        }

        private static DnsDatagram Query(Zone rootZone, string domain, DnsResourceRecordType type, bool enableIPv6)
        {
            Zone closestZone = GetClosestZone(rootZone, domain);
            DnsResourceRecord[] soaAuthority = null;

            if (rootZone._authoritativeZone)
            {
                soaAuthority = closestZone.GetRecord(closestZone.Name, DnsResourceRecordType.SOA);
                if (soaAuthority == null)
                    return null; //authoritative zone not found
            }

            DnsResourceRecord[] answer = closestZone.GetRecord(domain, type);
            DnsResourceRecord[] authority = null;
            DnsResourceRecord[] additional = null;

            if (answer == null)
            {
                if (rootZone._authoritativeZone)
                {
                    //domain name doesnt exists in authoritative zone
                    authority = soaAuthority;
                }
                else
                {
                    //domain name doesnt exists in cache; return closest available authority NS records
                    string closestZoneName = closestZone.Name;

                    while (true)
                    {
                        authority = closestZone.GetRecord(closestZoneName, DnsResourceRecordType.NS);

                        if ((authority != null) && (authority[0].Type == DnsResourceRecordType.NS))
                            break;

                        int i = closestZoneName.IndexOf('.');
                        if (i < 0)
                            closestZoneName = "";
                        else
                            closestZoneName = closestZoneName.Substring(i + 1);

                        closestZone = GetClosestZone(rootZone, closestZoneName);
                    }
                }
            }
            else if (rootZone._authoritativeZone && (answer.Length == 0))
            {
                //no records available for requested type
                authority = closestZone.GetRecord(domain, DnsResourceRecordType.NS);

                if (authority.Length == 0)
                    authority = soaAuthority;
            }
            else if (!rootZone._authoritativeZone && (answer[0].RDATA == null) || (answer[0].RDATA is DnsEmptyRecord))
            {
                //NameError or Empty entry found in cache
                //return closest available SOA records
                string closestZoneName = closestZone.Name;

                while (true)
                {
                    authority = closestZone.GetRecord(closestZoneName, DnsResourceRecordType.SOA);

                    if (authority != null)
                        break;

                    int i = closestZoneName.IndexOf('.');
                    if (i < 0)
                        closestZoneName = "";
                    else
                        closestZoneName = closestZoneName.Substring(i + 1);

                    closestZone = GetClosestZone(rootZone, closestZoneName);
                }
            }
            else if (rootZone._authoritativeZone && (type != DnsResourceRecordType.NS) && (type != DnsResourceRecordType.ANY) && ((type == DnsResourceRecordType.CNAME) || (answer[0].Type != DnsResourceRecordType.CNAME)))
            {
                authority = closestZone.GetRecord(closestZone.Name, DnsResourceRecordType.NS);
            }

            //fill in glue records for NS records in authority
            if ((authority != null) && (authority[0].Type != DnsResourceRecordType.SOA))
            {
                List<DnsResourceRecord> additionalList = new List<DnsResourceRecord>();
                Zone closestNSZone = null;

                foreach (DnsResourceRecord record in authority)
                {
                    DnsNSRecord nsRecord = record.RDATA as DnsNSRecord;

                    if ((closestNSZone == null) || !nsRecord.NSDomainName.EndsWith(closestNSZone._name))
                        closestNSZone = GetClosestZone(rootZone, nsRecord.NSDomainName);

                    DnsResourceRecord[] nsAnswersA = closestNSZone.GetRecord(nsRecord.NSDomainName, DnsResourceRecordType.A);
                    if (nsAnswersA != null)
                    {
                        if ((answer != null) && (type == DnsResourceRecordType.A))
                        {
                            foreach (DnsResourceRecord nsAnswerA in nsAnswersA)
                            {
                                bool contains = false;

                                foreach (DnsResourceRecord ans in answer)
                                {
                                    if (ans == nsAnswerA)
                                    {
                                        contains = true;
                                        break;
                                    }
                                }

                                if (!contains)
                                    additionalList.Add(nsAnswerA);
                            }
                        }
                        else
                        {
                            additionalList.AddRange(nsAnswersA);
                        }
                    }

                    if (enableIPv6)
                    {
                        DnsResourceRecord[] nsAnswersAAAA = closestNSZone.GetRecord(nsRecord.NSDomainName, DnsResourceRecordType.AAAA);
                        if (nsAnswersAAAA != null)
                        {
                            if ((answer != null) && (type == DnsResourceRecordType.AAAA))
                            {
                                foreach (DnsResourceRecord nsAnswerAAAA in nsAnswersAAAA)
                                {
                                    bool contains = false;

                                    foreach (DnsResourceRecord ans in answer)
                                    {
                                        if (ans == nsAnswerAAAA)
                                        {
                                            contains = true;
                                            break;
                                        }
                                    }

                                    if (!contains)
                                        additionalList.Add(nsAnswerAAAA);
                                }
                            }
                            else
                            {
                                additionalList.AddRange(nsAnswersAAAA);
                            }
                        }
                    }
                }

                additional = additionalList.ToArray();
            }

            return new DnsDatagram(null, null, answer, authority, additional);
        }

        #endregion

        #region public static

        public static Zone CreateZone(Zone rootZone, string domain)
        {
            Zone currentZone = rootZone;
            string[] path = ConvertDomainToPath(domain);

            for (int i = 0; i < path.Length; i++)
            {
                string nextZoneLabel = path[i];

                ReaderWriterLockSlim currentSubZoneLock = currentZone._subZoneLock;
                currentSubZoneLock.EnterWriteLock();
                try
                {
                    if (currentZone._subZone.ContainsKey(nextZoneLabel))
                    {
                        currentZone = currentZone._subZone[nextZoneLabel];
                    }
                    else
                    {
                        string zoneName = nextZoneLabel;

                        if (currentZone._name != "")
                            zoneName += "." + currentZone._name;

                        Zone nextZone = new Zone(zoneName, currentZone._authoritativeZone);
                        currentZone._subZone.Add(nextZoneLabel, nextZone);

                        currentZone = nextZone;
                    }
                }
                finally
                {
                    currentSubZoneLock.ExitWriteLock();
                }
            }

            return currentZone;
        }

        public static Zone GetClosestZone(Zone rootZone, string domain)
        {
            Zone currentZone = rootZone;
            string[] path = ConvertDomainToPath(domain);

            for (int i = 0; i < path.Length; i++)
            {
                string nextZoneLabel = path[i];

                ReaderWriterLockSlim currentSubZoneLock = currentZone._subZoneLock;
                currentSubZoneLock.EnterReadLock();
                try
                {
                    if (currentZone._subZone.ContainsKey(nextZoneLabel))
                        currentZone = currentZone._subZone[nextZoneLabel];
                    else
                        return currentZone;
                }
                finally
                {
                    currentSubZoneLock.ExitReadLock();
                }
            }

            return currentZone;
        }

        public static void DeleteZone(Zone rootZone, string domain)
        {
            Zone currentZone = rootZone;
            string[] path = ConvertDomainToPath(domain);

            //find parent zone
            for (int i = 0; i < path.Length - 1; i++)
            {
                string nextZoneLabel = path[i];

                ReaderWriterLockSlim currentSubZoneLock = currentZone._subZoneLock;
                currentSubZoneLock.EnterReadLock();
                try
                {
                    if (currentZone._subZone.ContainsKey(nextZoneLabel))
                        currentZone = currentZone._subZone[nextZoneLabel];
                    else
                        return;
                }
                finally
                {
                    currentSubZoneLock.ExitReadLock();
                }
            }

            currentZone._subZoneLock.EnterWriteLock();
            try
            {
                currentZone._subZone.Remove(path[path.Length - 1]);
            }
            finally
            {
                currentZone._subZoneLock.ExitWriteLock();
            }
        }

        public static DnsDatagram Query(Zone rootZone, DnsDatagram request, bool enableIPv6)
        {
            bool authoritativeAnswer = false;
            DnsResponseCode RCODE = DnsResponseCode.Refused;
            List<DnsResourceRecord> answerList = new List<DnsResourceRecord>();
            List<DnsResourceRecord> authorityList = new List<DnsResourceRecord>();
            List<DnsResourceRecord> additionalList = new List<DnsResourceRecord>();

            foreach (DnsQuestionRecord question in request.Question)
            {
                DnsDatagram response = Zone.Query(rootZone, question.Name, question.Type, enableIPv6);

                if (response != null)
                {
                    #region zone found

                    authoritativeAnswer = rootZone._authoritativeZone;

                    if (response.Answer == null)
                    {
                        if (authoritativeAnswer)
                            RCODE = DnsResponseCode.NameError; //domain does not exists in authoritative zone
                        else
                            RCODE = DnsResponseCode.Refused; //domain does not exists in cache
                    }
                    else
                    {
                        #region domain exists

                        RCODE = DnsResponseCode.NoError;

                        if (response.Answer.Length > 0)
                        {
                            if (!authoritativeAnswer && (response.Answer[0].RDATA == null))
                            {
                                //name error set in cache
                                RCODE = DnsResponseCode.NameError;
                            }
                            else if (!authoritativeAnswer && (response.Answer[0].RDATA is DnsEmptyRecord))
                            {
                                //empty entry set in cache; do nothing
                            }
                            else
                            {
                                answerList.AddRange(response.Answer);

                                if ((response.Answer[0].Type == DnsResourceRecordType.CNAME) && (question.Type != DnsResourceRecordType.CNAME))
                                {
                                    //resolve CNAME domain name
                                    DnsCNAMERecord cnameRecord = response.Answer[0].RDATA as DnsCNAMERecord;

                                    DnsDatagram cnameResponse = Zone.Query(rootZone, cnameRecord.CNAMEDomainName, question.Type, enableIPv6);
                                    if ((cnameResponse != null) && (cnameResponse.Answer != null))
                                    {
                                        if (!authoritativeAnswer && (cnameResponse.Answer[0].RDATA == null))
                                        {
                                            //name error set in cache
                                            RCODE = DnsResponseCode.NameError;
                                        }
                                        else if (!authoritativeAnswer && (cnameResponse.Answer[0].RDATA is DnsEmptyRecord))
                                        {
                                            //empty entry set in cache; do nothing
                                        }
                                        else
                                        {
                                            answerList.AddRange(cnameResponse.Answer);

                                            if (cnameResponse.Authority != null)
                                                authorityList.AddRange(cnameResponse.Authority);

                                            if (cnameResponse.Additional != null)
                                                additionalList.AddRange(cnameResponse.Additional);
                                        }
                                    }
                                }
                            }
                        }

                        #endregion
                    }

                    if ((response.Authority != null) && (response.Authority.Length > 0))
                        authorityList.AddRange(response.Authority);

                    if ((response.Additional != null) && (response.Additional.Length > 0))
                        additionalList.AddRange(response.Additional);

                    #endregion
                }
            }

            return new DnsDatagram(new DnsHeader(request.Header.Identifier, true, DnsOpcode.StandardQuery, authoritativeAnswer, false, request.Header.RecursionDesired, !rootZone._authoritativeZone, false, false, RCODE, Convert.ToUInt16(request.Question.Length), Convert.ToUInt16(answerList.Count), Convert.ToUInt16(authorityList.Count), Convert.ToUInt16(additionalList.Count)), request.Question, answerList.ToArray(), authorityList.ToArray(), additionalList.ToArray());
        }

        public static void CacheResponse(Zone rootZone, DnsDatagram response)
        {
            if (rootZone._authoritativeZone)
                throw new DnsServerException("Cannot cache response into authoritative zone.");

            if (!response.Header.IsResponse)
                return;

            //combine all records in the response
            List<DnsResourceRecord> allRecords = new List<DnsResourceRecord>();

            switch (response.Header.RCODE)
            {
                case DnsResponseCode.NameError:
                    {
                        string authorityZone = null;
                        uint ttl = 60;

                        if ((response.Authority.Length > 0) && (response.Authority[0].Type == DnsResourceRecordType.SOA))
                        {
                            authorityZone = response.Authority[0].Name;
                            ttl = (response.Authority[0].RDATA as DnsSOARecord).Minimum;
                        }

                        foreach (DnsQuestionRecord question in response.Question)
                        {
                            if (authorityZone == null)
                                authorityZone = question.Name;

                            Zone zone = CreateZone(rootZone, authorityZone);
                            zone.SetRecord(new DnsResourceRecord[] { new DnsResourceRecord(question.Name, question.Type, DnsClass.Internet, ttl, null) });
                        }
                    }
                    break;

                case DnsResponseCode.NoError:
                    if (response.Answer.Length == 0)
                    {
                        if (response.Header.AuthoritativeAnswer)
                        {
                            uint ttl = 60;

                            if ((response.Authority.Length > 0) && (response.Authority[0].Type == DnsResourceRecordType.SOA))
                                ttl = (response.Authority[0].RDATA as DnsSOARecord).Minimum;

                            foreach (DnsQuestionRecord question in response.Question)
                            {
                                if (question.Type == DnsResourceRecordType.NS)
                                    continue;

                                Zone zone = CreateZone(rootZone, question.Name);
                                zone.SetRecord(new DnsResourceRecord[] { new DnsResourceRecord(question.Name, question.Type, DnsClass.Internet, ttl, new DnsEmptyRecord()) });
                            }
                        }
                    }
                    else
                    {
                        foreach (DnsQuestionRecord question in response.Question)
                        {
                            uint ttl = 60;

                            if (question.Type == DnsResourceRecordType.ANY)
                            {
                                Zone zone = CreateZone(rootZone, question.Name);

                                DnsResourceRecord[] soaRecord = zone.GetRecord(question.Name, DnsResourceRecordType.SOA);
                                if ((soaRecord != null) && (soaRecord.Length > 0))
                                    ttl = (soaRecord[0].RDATA as DnsSOARecord).Minimum;

                                zone.SetRecord(new DnsResourceRecord[] { new DnsResourceRecord(question.Name, DnsResourceRecordType.ANY, DnsClass.Internet, ttl, new DnsEmptyRecord()) });
                            }
                        }

                        allRecords.AddRange(response.Answer);
                    }
                    break;

                default:
                    return; //nothing to do
            }

            allRecords.AddRange(response.Authority);
            allRecords.AddRange(response.Additional);

            //group all records by domain and type
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

            //add grouped entries into cache zone
            foreach (KeyValuePair<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> cacheEntry in cacheEntries)
            {
                string domain = cacheEntry.Key;
                Zone zone = CreateZone(rootZone, domain);

                foreach (KeyValuePair<DnsResourceRecordType, List<DnsResourceRecord>> cacheTypeEntry in cacheEntry.Value)
                {
                    DnsResourceRecord[] records = cacheTypeEntry.Value.ToArray();

                    foreach (DnsResourceRecord record in records)
                        record.SetExpiry();

                    zone.SetRecord(records);
                }
            }
        }

        #endregion

        #region public

        public void SetRecord(string domain, DnsResourceRecordType type, uint ttl, DnsResourceRecordData[] records)
        {
            DnsResourceRecord[] resourceRecords = new DnsResourceRecord[records.Length];

            for (int i = 0; i < resourceRecords.Length; i++)
                resourceRecords[i] = new DnsResourceRecord(domain, type, DnsClass.Internet, ttl, records[i]);

            SetRecord(resourceRecords);
        }

        public DnsResourceRecord[] GetRecord(string domain, DnsResourceRecordType type)
        {
            _zoneEntriesLock.EnterReadLock();
            try
            {
                Dictionary<DnsResourceRecordType, DnsResourceRecord[]> zoneTypeEntries = null;

                if (_zoneEntries.ContainsKey(domain))
                {
                    zoneTypeEntries = _zoneEntries[domain];
                }
                else if (_authoritativeZone && (_zoneEntries.Count > 0))
                {
                    //check for wildcard entry
                    string subDomainName = domain;

                    while (true)
                    {
                        if (subDomainName.Equals(_name, StringComparison.CurrentCultureIgnoreCase))
                            break;

                        int i = subDomainName.IndexOf('.');
                        if (i < 0)
                            break;

                        subDomainName = subDomainName.Substring(i + 1);

                        string wildCardSubDomain = "*." + subDomainName;
                        if (_zoneEntries.ContainsKey(wildCardSubDomain))
                        {
                            zoneTypeEntries = _zoneEntries[wildCardSubDomain];

                            //create new resource records for wild card entry
                            Dictionary<DnsResourceRecordType, DnsResourceRecord[]> newZoneTypeEntries = new Dictionary<DnsResourceRecordType, DnsResourceRecord[]>(zoneTypeEntries.Count);

                            foreach (KeyValuePair<DnsResourceRecordType, DnsResourceRecord[]> entry in zoneTypeEntries)
                            {
                                DnsResourceRecord[] zoneEntryRecords = entry.Value;
                                DnsResourceRecord[] resourceRecords = new DnsResourceRecord[zoneEntryRecords.Length];

                                for (int j = 0; j < zoneEntryRecords.Length; j++)
                                {
                                    DnsResourceRecord zoneEntryRecord = zoneEntryRecords[j];
                                    resourceRecords[j] = new DnsResourceRecord(domain, zoneEntryRecord.Type, zoneEntryRecord.Class, zoneEntryRecord.TTLValue, zoneEntryRecord.RDATA);
                                }

                                newZoneTypeEntries.Add(entry.Key, resourceRecords);
                            }

                            zoneTypeEntries = newZoneTypeEntries;
                            break;
                        }
                    }

                    if (zoneTypeEntries == null)
                        return null;
                }
                else
                {
                    return null;
                }

                if (zoneTypeEntries.ContainsKey(DnsResourceRecordType.CNAME))
                {
                    DnsResourceRecord[] zoneEntry = zoneTypeEntries[DnsResourceRecordType.CNAME];

                    if (!_authoritativeZone && (zoneEntry[0].TTLValue < 1))
                        return null; //domain does not exists in cache since expired
                    else
                        return zoneEntry; //return CNAME record
                }
                else if (type == DnsResourceRecordType.ANY)
                {
                    if ((!_authoritativeZone) && !zoneTypeEntries.ContainsKey(type))
                        return null; //domain does not exists in cache

                    List<DnsResourceRecord> records = new List<DnsResourceRecord>(5);

                    foreach (KeyValuePair<DnsResourceRecordType, DnsResourceRecord[]> entry in zoneTypeEntries)
                    {
                        if (entry.Key != DnsResourceRecordType.ANY)
                            records.AddRange(entry.Value);
                    }

                    return records.ToArray(); //all authoritative records
                }
                else if (zoneTypeEntries.ContainsKey(type))
                {
                    DnsResourceRecord[] zoneEntry = zoneTypeEntries[type];

                    if (_authoritativeZone || (_name == ""))
                    {
                        return zoneEntry; //records found in authoritative zone or root hints from cache
                    }
                    else
                    {
                        if ((zoneEntry[0].TTLValue < 1))
                            return null; //domain does not exists in cache since expired
                        else
                            return zoneEntry; //records found in cache
                    }
                }
                else
                {
                    if (_authoritativeZone)
                        return new DnsResourceRecord[] { }; //no records in authoritative zone
                    else
                        return null; //domain does not exists in cache
                }
            }
            finally
            {
                _zoneEntriesLock.ExitReadLock();
            }
        }

        public void DeleteRecord(string domain, DnsResourceRecordType type)
        {
            _zoneEntriesLock.EnterWriteLock();
            try
            {
                Dictionary<DnsResourceRecordType, DnsResourceRecord[]> zoneTypeEntries;

                if (_zoneEntries.ContainsKey(domain))
                {
                    zoneTypeEntries = _zoneEntries[domain];

                    zoneTypeEntries.Remove(type);

                    if (zoneTypeEntries.Count < 1)
                        _zoneEntries.Remove(domain);
                }
            }
            finally
            {
                _zoneEntriesLock.ExitWriteLock();
            }
        }

        public override string ToString()
        {
            return _name;
        }

        #endregion

        #region properties

        public string Name
        { get { return _name; } }

        #endregion
    }

    class DnsEmptyRecord : DnsResourceRecordData
    {
        #region constructor

        public DnsEmptyRecord()
        { }

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
    }
}
