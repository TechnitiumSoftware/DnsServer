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

using DnsServerCore.Dns.ResourceRecords;
using DnsServerCore.Dns.Zones;
using System.Collections.Generic;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns.ZoneManagers
{
    public sealed class CacheZoneManager : DnsCache
    {
        #region variables

        const uint FAILURE_RECORD_TTL = 30u;
        const uint NEGATIVE_RECORD_TTL = 300u;
        const uint MINIMUM_RECORD_TTL = 10u;
        const uint SERVE_STALE_TTL = 3 * 24 * 60 * 60; //3 days serve stale ttl as per https://www.rfc-editor.org/rfc/rfc8767.html suggestion

        readonly ZoneTree<CacheZone> _root = new ZoneTree<CacheZone>();

        #endregion

        #region constructor

        public CacheZoneManager()
            : base(FAILURE_RECORD_TTL, NEGATIVE_RECORD_TTL, MINIMUM_RECORD_TTL, SERVE_STALE_TTL)
        { }

        #endregion

        #region protected

        protected override void CacheRecords(IReadOnlyList<DnsResourceRecord> resourceRecords)
        {
            //read and set glue records from base class
            foreach (DnsResourceRecord resourceRecord in resourceRecords)
            {
                IReadOnlyList<DnsResourceRecord> glueRecords = GetGlueRecordsFrom(resourceRecord);
                if (glueRecords.Count > 0)
                    resourceRecord.SetGlueRecords(glueRecords);
            }

            if (resourceRecords.Count == 1)
            {
                CacheZone zone = _root.GetOrAdd(resourceRecords[0].Name, delegate (string key)
                {
                    return new CacheZone(resourceRecords[0].Name);
                });

                zone.SetRecords(resourceRecords[0].Type, resourceRecords);
            }
            else
            {
                Dictionary<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> groupedByDomainRecords = DnsResourceRecord.GroupRecords(resourceRecords);

                //add grouped records
                foreach (KeyValuePair<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> groupedByTypeRecords in groupedByDomainRecords)
                {
                    CacheZone zone = _root.GetOrAdd(groupedByTypeRecords.Key, delegate (string key)
                    {
                        return new CacheZone(groupedByTypeRecords.Key);
                    });

                    foreach (KeyValuePair<DnsResourceRecordType, List<DnsResourceRecord>> groupedRecords in groupedByTypeRecords.Value)
                        zone.SetRecords(groupedRecords.Key, groupedRecords.Value);
                }
            }
        }

        #endregion

        #region private

        private List<DnsResourceRecord> GetAdditionalRecords(IReadOnlyCollection<DnsResourceRecord> refRecords, bool serveStale)
        {
            List<DnsResourceRecord> additionalRecords = new List<DnsResourceRecord>();

            foreach (DnsResourceRecord refRecord in refRecords)
            {
                switch (refRecord.Type)
                {
                    case DnsResourceRecordType.NS:
                        ResolveAdditionalRecords(refRecord, (refRecord.RDATA as DnsNSRecord).NameServer, serveStale, additionalRecords);
                        break;

                    case DnsResourceRecordType.MX:
                        ResolveAdditionalRecords(refRecord, (refRecord.RDATA as DnsMXRecord).Exchange, serveStale, additionalRecords);
                        break;

                    case DnsResourceRecordType.SRV:
                        ResolveAdditionalRecords(refRecord, (refRecord.RDATA as DnsSRVRecord).Target, serveStale, additionalRecords);
                        break;
                }
            }

            return additionalRecords;
        }

        private void ResolveAdditionalRecords(DnsResourceRecord refRecord, string domain, bool serveStale, List<DnsResourceRecord> additionalRecords)
        {
            IReadOnlyList<DnsResourceRecord> glueRecords = refRecord.GetGlueRecords();
            if (glueRecords.Count > 0)
            {
                bool added = false;

                foreach (DnsResourceRecord glueRecord in glueRecords)
                {
                    if (!glueRecord.IsStale)
                    {
                        added = true;
                        additionalRecords.Add(glueRecord);
                    }
                }

                if (added)
                    return;
            }

            CacheZone cacheZone = _root.FindZone(domain, out _, out _, out _);
            if (cacheZone != null)
            {
                {
                    IReadOnlyList<DnsResourceRecord> records = cacheZone.QueryRecords(DnsResourceRecordType.A, serveStale, true);
                    if ((records.Count > 0) && (records[0].RDATA is DnsARecord))
                        additionalRecords.AddRange(records);
                }

                {
                    IReadOnlyList<DnsResourceRecord> records = cacheZone.QueryRecords(DnsResourceRecordType.AAAA, serveStale, true);
                    if ((records.Count > 0) && (records[0].RDATA is DnsAAAARecord))
                        additionalRecords.AddRange(records);
                }
            }
        }

        #endregion

        #region public

        public void DoMaintenance()
        {
            foreach (CacheZone zone in _root)
            {
                zone.RemoveExpiredRecords();

                if (zone.IsEmpty)
                    _root.TryRemove(zone.Name, out _); //remove empty zone
            }
        }

        public override void Flush()
        {
            _root.Clear();
        }

        public bool DeleteZone(string domain)
        {
            return _root.TryRemove(domain, out _);
        }

        public List<string> ListSubDomains(string domain)
        {
            return _root.ListSubDomains(domain);
        }

        public List<DnsResourceRecord> ListAllRecords(string domain)
        {
            if (_root.TryGet(domain, out CacheZone zone))
                return zone.ListAllRecords();

            return new List<DnsResourceRecord>(0);
        }

        public DnsDatagram QueryClosestDelegation(DnsDatagram request)
        {
            _ = _root.FindZone(request.Question[0].Name, out CacheZone delegation, out _, out _);
            if (delegation == null)
            {
                //no cached delegation found
                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, false, DnsResponseCode.Refused, request.Question);
            }

            //return closest name servers in delegation
            IReadOnlyList<DnsResourceRecord> authority = delegation.QueryRecords(DnsResourceRecordType.NS, false, true);
            List<DnsResourceRecord> additional = GetAdditionalRecords(authority, false);

            return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, false, DnsResponseCode.NoError, request.Question, null, authority, additional);
        }

        public override DnsDatagram Query(DnsDatagram request, bool serveStale = false)
        {
            CacheZone zone = _root.FindZone(request.Question[0].Name, out CacheZone delegation, out _, out _);
            if (zone == null)
            {
                //zone not found
                if (delegation == null)
                {
                    //no cached delegation found
                    return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, false, DnsResponseCode.Refused, request.Question);
                }

                //return closest name servers in delegation
                IReadOnlyList<DnsResourceRecord> authority = delegation.QueryRecords(DnsResourceRecordType.NS, serveStale, true);
                List<DnsResourceRecord> additional = GetAdditionalRecords(authority, serveStale);

                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, false, DnsResponseCode.NoError, request.Question, null, authority, additional);
            }

            //zone found
            IReadOnlyList<DnsResourceRecord> answers = zone.QueryRecords(request.Question[0].Type, serveStale, false);
            if (answers.Count > 0)
            {
                //answer found in cache
                if (answers[0].RDATA is DnsEmptyRecord)
                {
                    DnsResourceRecord[] authority = null;
                    DnsResourceRecord soaRecord = (answers[0].RDATA as DnsEmptyRecord).Authority;
                    if (soaRecord != null)
                        authority = new DnsResourceRecord[] { soaRecord };

                    return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, false, DnsResponseCode.NoError, request.Question, null, authority);
                }

                if (answers[0].RDATA is DnsNXRecord)
                {
                    DnsResourceRecord[] authority = null;
                    DnsResourceRecord soaRecord = (answers[0].RDATA as DnsNXRecord).Authority;
                    if (soaRecord != null)
                        authority = new DnsResourceRecord[] { soaRecord };

                    return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, false, DnsResponseCode.NameError, request.Question, null, authority);
                }

                if (answers[0].RDATA is DnsANYRecord)
                {
                    DnsANYRecord anyRR = answers[0].RDATA as DnsANYRecord;
                    return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, false, DnsResponseCode.NoError, request.Question, anyRR.Records);
                }

                if (answers[0].RDATA is DnsFailureRecord)
                    return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, false, (answers[0].RDATA as DnsFailureRecord).RCODE, request.Question);

                IReadOnlyList<DnsResourceRecord> additional = null;

                switch (request.Question[0].Type)
                {
                    case DnsResourceRecordType.NS:
                    case DnsResourceRecordType.MX:
                    case DnsResourceRecordType.SRV:
                        additional = GetAdditionalRecords(answers, serveStale);
                        break;
                }

                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, false, DnsResponseCode.NoError, request.Question, answers, null, additional);
            }
            else
            {
                //no answer in cache; check for closest delegation if any
                if (delegation == null)
                {
                    //no cached delegation found
                    return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, false, DnsResponseCode.Refused, request.Question);
                }

                //return closest name servers in delegation
                IReadOnlyList<DnsResourceRecord> authority = delegation.QueryRecords(DnsResourceRecordType.NS, false, true);
                List<DnsResourceRecord> additional = GetAdditionalRecords(authority, false);

                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, false, DnsResponseCode.NoError, request.Question, null, authority, additional);
            }
        }

        #endregion
    }
}
