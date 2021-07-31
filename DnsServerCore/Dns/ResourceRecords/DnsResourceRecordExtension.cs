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

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns.ResourceRecords
{
    static class DnsResourceRecordExtension
    {
        public static void SetGlueRecords(this DnsResourceRecord record, IReadOnlyList<DnsResourceRecord> glueRecords)
        {
            if (record.Tag is not DnsResourceRecordInfo rrInfo)
            {
                rrInfo = new DnsResourceRecordInfo();
                record.Tag = rrInfo;
            }

            rrInfo.GlueRecords = glueRecords;
        }

        public static void SetGlueRecords(this DnsResourceRecord record, string glueAddresses)
        {
            string[] addresses = glueAddresses.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
            List<IPAddress> ipAddresses = new List<IPAddress>(addresses.Length);

            foreach (string address in addresses)
                ipAddresses.Add(IPAddress.Parse(address.Trim()));

            SetGlueRecords(record, ipAddresses);
        }

        public static void SetGlueRecords(this DnsResourceRecord record, IReadOnlyList<IPAddress> glueAddresses)
        {
            if (record.RDATA is not DnsNSRecord nsRecord)
                throw new InvalidOperationException();

            string domain = nsRecord.NameServer;

            DnsResourceRecord[] glueRecords = new DnsResourceRecord[glueAddresses.Count];

            for (int i = 0; i < glueRecords.Length; i++)
            {
                switch (glueAddresses[i].AddressFamily)
                {
                    case AddressFamily.InterNetwork:
                        glueRecords[i] = new DnsResourceRecord(domain, DnsResourceRecordType.A, DnsClass.IN, record.TtlValue, new DnsARecord(glueAddresses[i]));
                        break;

                    case AddressFamily.InterNetworkV6:
                        glueRecords[i] = new DnsResourceRecord(domain, DnsResourceRecordType.AAAA, DnsClass.IN, record.TtlValue, new DnsAAAARecord(glueAddresses[i]));
                        break;
                }
            }

            SetGlueRecords(record, glueRecords);
        }

        public static void SyncGlueRecords(this DnsResourceRecord record, IReadOnlyList<DnsResourceRecord> allGlueRecords)
        {
            if (record.RDATA is not DnsNSRecord nsRecord)
                throw new InvalidOperationException();

            string domain = nsRecord.NameServer;

            List<DnsResourceRecord> foundGlueRecords = new List<DnsResourceRecord>(2);

            foreach (DnsResourceRecord glueRecord in allGlueRecords)
            {
                switch (glueRecord.Type)
                {
                    case DnsResourceRecordType.A:
                    case DnsResourceRecordType.AAAA:
                        if (glueRecord.Name.Equals(domain, StringComparison.OrdinalIgnoreCase))
                            foundGlueRecords.Add(glueRecord);

                        break;
                }
            }

            if (foundGlueRecords.Count > 0)
                SetGlueRecords(record, foundGlueRecords);
            else
                SetGlueRecords(record, Array.Empty<DnsResourceRecord>());
        }

        public static void SyncGlueRecords(this DnsResourceRecord record, IReadOnlyCollection<DnsResourceRecord> deletedGlueRecords, IReadOnlyCollection<DnsResourceRecord> addedGlueRecords)
        {
            if (record.RDATA is not DnsNSRecord nsRecord)
                throw new InvalidOperationException();

            bool updated = false;

            List<DnsResourceRecord> updatedGlueRecords = new List<DnsResourceRecord>();
            IReadOnlyList<DnsResourceRecord> existingGlueRecords = GetGlueRecords(record);

            foreach (DnsResourceRecord existingGlueRecord in existingGlueRecords)
            {
                if (deletedGlueRecords.Contains(existingGlueRecord))
                    updated = true; //skipped to delete existing glue record
                else
                    updatedGlueRecords.Add(existingGlueRecord);
            }

            string domain = nsRecord.NameServer;

            foreach (DnsResourceRecord addedGlueRecord in addedGlueRecords)
            {
                switch (addedGlueRecord.Type)
                {
                    case DnsResourceRecordType.A:
                    case DnsResourceRecordType.AAAA:
                        if (addedGlueRecord.Name.Equals(domain, StringComparison.OrdinalIgnoreCase))
                        {
                            updatedGlueRecords.Add(addedGlueRecord);
                            updated = true;
                        }
                        break;
                }
            }

            if (updated)
                SetGlueRecords(record, updatedGlueRecords);
        }

        public static IReadOnlyList<DnsResourceRecord> GetGlueRecords(this DnsResourceRecord record)
        {
            if (record.Tag is DnsResourceRecordInfo rrInfo)
            {
                IReadOnlyList<DnsResourceRecord> glueRecords = rrInfo.GlueRecords;
                if (glueRecords is null)
                    return Array.Empty<DnsResourceRecord>();

                return glueRecords;
            }

            return Array.Empty<DnsResourceRecord>();
        }

        public static bool IsDisabled(this DnsResourceRecord record)
        {
            if (record.Tag is DnsResourceRecordInfo rrInfo)
                return rrInfo.Disabled;

            return false;
        }

        public static void Disable(this DnsResourceRecord record)
        {
            if (record.Tag is not DnsResourceRecordInfo rrInfo)
            {
                rrInfo = new DnsResourceRecordInfo();
                record.Tag = rrInfo;
            }

            rrInfo.Disabled = true;
        }

        public static void Enable(this DnsResourceRecord record)
        {
            if (record.Tag is DnsResourceRecordInfo rrInfo)
                rrInfo.Disabled = false;
        }

        public static string GetComments(this DnsResourceRecord record)
        {
            if (record.Tag is DnsResourceRecordInfo rrInfo)
                return rrInfo.Comments;

            return null;
        }

        public static void SetComments(this DnsResourceRecord record, string value)
        {
            if (record.Tag is not DnsResourceRecordInfo rrInfo)
            {
                rrInfo = new DnsResourceRecordInfo();
                record.Tag = rrInfo;
            }

            rrInfo.Comments = value;
        }

        public static DateTime GetDeletedOn(this DnsResourceRecord record)
        {
            if (record.Tag is DnsResourceRecordInfo rrInfo)
                return rrInfo.DeletedOn;

            return DateTime.MinValue;
        }

        public static void SetDeletedOn(this DnsResourceRecord record, DateTime value)
        {
            if (record.Tag is not DnsResourceRecordInfo rrInfo)
            {
                rrInfo = new DnsResourceRecordInfo();
                record.Tag = rrInfo;
            }

            rrInfo.DeletedOn = value;
        }

        public static void SetPrimaryNameServers(this DnsResourceRecord record, IReadOnlyList<NameServerAddress> primaryNameServers)
        {
            if (record.Tag is not DnsResourceRecordInfo rrInfo)
            {
                rrInfo = new DnsResourceRecordInfo();
                record.Tag = rrInfo;
            }

            rrInfo.PrimaryNameServers = primaryNameServers;
        }

        public static void SetPrimaryNameServers(this DnsResourceRecord record, string primaryNameServers)
        {
            string[] nameServerAddresses = primaryNameServers.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
            List<NameServerAddress> nameServers = new List<NameServerAddress>(nameServerAddresses.Length);

            foreach (string nameServerAddress in nameServerAddresses)
                nameServers.Add(new NameServerAddress(nameServerAddress));

            SetPrimaryNameServers(record, nameServers);
        }

        public static IReadOnlyList<NameServerAddress> GetPrimaryNameServers(this DnsResourceRecord record)
        {
            if (record.Tag is DnsResourceRecordInfo rrInfo)
            {
                IReadOnlyList<NameServerAddress> primaryNameServers = rrInfo.PrimaryNameServers;
                if (primaryNameServers is null)
                    return Array.Empty<NameServerAddress>();

                return primaryNameServers;
            }

            return Array.Empty<NameServerAddress>();
        }

        public static DnsResourceRecordInfo GetRecordInfo(this DnsResourceRecord record)
        {
            if (record.Tag is not DnsResourceRecordInfo rrInfo)
            {
                rrInfo = new DnsResourceRecordInfo();
                record.Tag = rrInfo;
            }

            return rrInfo;
        }

        public static void CopyRecordInfoFrom(this DnsResourceRecord record, DnsResourceRecord otherRecord)
        {
            record.Tag = otherRecord.Tag;
        }
    }
}
