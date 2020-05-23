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
using System.Net;
using System.Net.Sockets;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns.Zones
{
    public static class DnsResourceRecordExtension
    {
        public static void SetGlueRecords(this DnsResourceRecord nsRecord, string glueAddresses)
        {
            List<IPAddress> addresses = new List<IPAddress>();

            foreach (string address in glueAddresses.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries))
                addresses.Add(IPAddress.Parse(address.Trim()));

            SetGlueRecords(nsRecord, addresses);
        }

        public static void SetGlueRecords(this DnsResourceRecord nsRecord, IReadOnlyList<IPAddress> glueAddresses)
        {
            DnsResourceRecordInfo rrInfo = nsRecord.Tag as DnsResourceRecordInfo;
            if (rrInfo == null)
            {
                rrInfo = new DnsResourceRecordInfo();
                nsRecord.Tag = rrInfo;
            }

            DnsResourceRecord[] glueRecords = new DnsResourceRecord[glueAddresses.Count];

            for (int i = 0; i < glueRecords.Length; i++)
            {
                switch (glueAddresses[i].AddressFamily)
                {
                    case AddressFamily.InterNetwork:
                        glueRecords[i] = new DnsResourceRecord((nsRecord.RDATA as DnsNSRecord).NSDomainName, DnsResourceRecordType.A, DnsClass.IN, nsRecord.TtlValue, new DnsARecord(glueAddresses[i]));
                        break;

                    case AddressFamily.InterNetworkV6:
                        glueRecords[i] = new DnsResourceRecord((nsRecord.RDATA as DnsNSRecord).NSDomainName, DnsResourceRecordType.AAAA, DnsClass.IN, nsRecord.TtlValue, new DnsAAAARecord(glueAddresses[i]));
                        break;
                }
            }

            rrInfo.GlueRecords = glueRecords;
        }

        public static IReadOnlyList<DnsResourceRecord> GetGlueRecords(this DnsResourceRecord nsRecord)
        {
            DnsResourceRecordInfo rrInfo = nsRecord.Tag as DnsResourceRecordInfo;
            if (rrInfo == null)
                return Array.Empty<DnsResourceRecord>();

            IReadOnlyList<DnsResourceRecord> glueRecords = rrInfo.GlueRecords;
            if ((glueRecords == null) || (glueRecords.Count == 0))
                return Array.Empty<DnsResourceRecord>();

            return glueRecords;
        }

        public static IReadOnlyList<DnsResourceRecord> GetGlueRecords(this IReadOnlyList<DnsResourceRecord> nsRecords)
        {
            if (nsRecords.Count == 1)
                return GetGlueRecords(nsRecords[0]);

            List<DnsResourceRecord> glueRecords = new List<DnsResourceRecord>(nsRecords.Count * 2);

            foreach (DnsResourceRecord nsRecord in nsRecords)
                glueRecords.AddRange(GetGlueRecords(nsRecord));

            return glueRecords;
        }

        public static bool IsDisabled(this DnsResourceRecord record)
        {
            DnsResourceRecordInfo rrInfo = record.Tag as DnsResourceRecordInfo;
            if (rrInfo == null)
                return false;

            else return rrInfo.Disabled;
        }

        public static void Disable(this DnsResourceRecord record)
        {
            DnsResourceRecordInfo rrInfo = record.Tag as DnsResourceRecordInfo;
            if (rrInfo == null)
            {
                rrInfo = new DnsResourceRecordInfo();
                record.Tag = rrInfo;
            }

            rrInfo.Disabled = true;
        }

        public static void Enable(this DnsResourceRecord record)
        {
            DnsResourceRecordInfo rrInfo = record.Tag as DnsResourceRecordInfo;
            if (rrInfo == null)
                return;

            rrInfo.Disabled = false;
        }
    }
}
