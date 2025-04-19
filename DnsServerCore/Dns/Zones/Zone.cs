/*
Technitium DNS Server
Copyright (C) 2025  Shreyas Zare (shreyas@technitium.com)

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
using System.Net;
using System.Net.Sockets;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns.Zones
{
    abstract class Zone
    {
        #region variables

        protected readonly string _name;
        protected readonly ConcurrentDictionary<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> _entries;

        #endregion

        #region constructor

        protected Zone(string name)
        {
            _name = name.ToLowerInvariant();
            _entries = new ConcurrentDictionary<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>>(-1, 5);
        }

        protected Zone(string name, int capacity)
        {
            _name = name.ToLowerInvariant();
            _entries = new ConcurrentDictionary<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>>(-1, capacity);
        }

        protected Zone(string name, ConcurrentDictionary<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> entries)
        {
            _name = name.ToLowerInvariant();
            _entries = entries;
        }

        #endregion

        #region static

        public static string GetReverseZone(IPAddress address, IPAddress subnetMask)
        {
            return GetReverseZone(address, subnetMask.GetSubnetMaskWidth());
        }

        public static string GetReverseZone(IPAddress address, int subnetMaskWidth)
        {
            int addressByteCount = Convert.ToInt32(Math.Ceiling(Convert.ToDecimal(subnetMaskWidth) / 8));
            byte[] addressBytes = address.GetAddressBytes();
            string reverseZone = "";

            switch (address.AddressFamily)
            {
                case AddressFamily.InterNetwork:
                    for (int i = 0; i < addressByteCount; i++)
                        reverseZone = addressBytes[i] + "." + reverseZone;

                    reverseZone += "in-addr.arpa";
                    break;

                case AddressFamily.InterNetworkV6:
                    for (int i = 0; i < addressByteCount; i++)
                        reverseZone = (addressBytes[i] & 0x0F).ToString("x") + "." + (addressBytes[i] >> 4).ToString("x") + "." + reverseZone;

                    reverseZone += "ip6.arpa";
                    break;

                default:
                    throw new NotSupportedException("AddressFamily not supported.");
            }

            return reverseZone;
        }

        #endregion

        #region public

        public virtual void ListAllRecords(List<DnsResourceRecord> records)
        {
            foreach (KeyValuePair<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> entry in _entries)
                records.AddRange(entry.Value);
        }

        public abstract bool ContainsNameServerRecords();

        public override string ToString()
        {
            return _name;
        }

        #endregion

        #region properties

        public string Name
        { get { return _name; } }

        public virtual bool IsEmpty
        { get { return _entries.IsEmpty; } }

        #endregion
    }
}
