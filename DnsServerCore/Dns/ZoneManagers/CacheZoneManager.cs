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
using System.Collections.Generic;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns.ZoneManagers
{
    public class CacheZoneManager : DnsCache
    {
        #region variables

        const uint FAILURE_RECORD_TTL = 30u;
        const uint NEGATIVE_RECORD_TTL = 300u;
        const uint MINIMUM_RECORD_TTL = 10u;
        const uint SERVE_STALE_TTL = 7 * 24 * 60 * 60; //7 days serve stale ttl as per draft-ietf-dnsop-serve-stale-04

        readonly protected ZoneTree<CacheZone> _root = new ZoneTree<CacheZone>();

        #endregion

        #region constructor

        public CacheZoneManager()
            : base(FAILURE_RECORD_TTL, NEGATIVE_RECORD_TTL, MINIMUM_RECORD_TTL, SERVE_STALE_TTL)
        { }

        #endregion

        #region protected

        protected override void CacheRecords(IReadOnlyList<DnsResourceRecord> resourceRecords)
        {
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

        private List<DnsResourceRecord> GetAdditionalRecords(IReadOnlyCollection<DnsResourceRecord> nsRecords, bool serveStale)
        {
            List<DnsResourceRecord> additionalRecords = new List<DnsResourceRecord>();

            foreach (DnsResourceRecord nsRecord in nsRecords)
            {
                if (nsRecord.Type != DnsResourceRecordType.NS)
                    continue;

                CacheZone cacheZone = _root.FindZone((nsRecord.RDATA as DnsNSRecord).NSDomainName, out _, out _, out _);
                if (cacheZone != null)
                {
                    {
                        IReadOnlyList<DnsResourceRecord> records = cacheZone.QueryRecords(DnsResourceRecordType.A, serveStale);
                        if ((records.Count > 0) && (records[0].RDATA is DnsARecord))
                            additionalRecords.AddRange(records);
                    }

                    {
                        IReadOnlyList<DnsResourceRecord> records = cacheZone.QueryRecords(DnsResourceRecordType.AAAA, serveStale);
                        if ((records.Count > 0) && (records[0].RDATA is DnsAAAARecord))
                            additionalRecords.AddRange(records);
                    }
                }
            }

            return additionalRecords;
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

        public void Flush()
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
            IReadOnlyList<DnsResourceRecord> authority = delegation.QueryRecords(DnsResourceRecordType.NS, false);
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
                IReadOnlyList<DnsResourceRecord> authority = delegation.QueryRecords(DnsResourceRecordType.NS, serveStale);
                List<DnsResourceRecord> additional = GetAdditionalRecords(authority, serveStale);

                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, false, DnsResponseCode.NoError, request.Question, null, authority, additional);
            }

            //zone found
            IReadOnlyList<DnsResourceRecord> answers = zone.QueryRecords(request.Question[0].Type, serveStale);
            if (answers.Count > 0)
            {
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

                if (request.Question[0].Type == DnsResourceRecordType.NS)
                    additional = GetAdditionalRecords(answers, serveStale);

                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, false, DnsResponseCode.NoError, request.Question, answers, null, additional);
            }

            //found nothing in cache
            return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, false, DnsResponseCode.Refused, request.Question);
        }

        #endregion
    }
}
