/*
Technitium DNS Server
Copyright (C) 2023  Shreyas Zare (shreyas@technitium.com)

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
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net;

namespace DnsServerSystemTrayApp
{
    public class DnsProvider : IComparable<DnsProvider>
    {
        #region variables

        public string Name;
        public ICollection<IPAddress> Addresses;

        #endregion

        #region constructor

        public DnsProvider(string name, ICollection<IPAddress> addresses)
        {
            this.Name = name;
            this.Addresses = addresses;
        }

        public DnsProvider(BinaryReader bR)
        {
            this.Name = bR.ReadShortString();
            this.Addresses = new List<IPAddress>();

            int count = bR.ReadInt32();

            for (int i = 0; i < count; i++)
                this.Addresses.Add(IPAddressExtensions.ReadFrom(bR));
        }

        #endregion

        #region static

        public static DnsProvider[] GetDefaultProviders()
        {
            return new DnsProvider[] {
                new DnsProvider("Technitium", new IPAddress[] { IPAddress.Loopback, IPAddress.IPv6Loopback }),
                new DnsProvider("Cloudflare", new IPAddress[] { IPAddress.Parse("1.1.1.1"), IPAddress.Parse("1.0.0.1"), IPAddress.Parse("[2606:4700:4700::1111]"), IPAddress.Parse("[2606:4700:4700::1001]") }),
                new DnsProvider("Google", new IPAddress[] { IPAddress.Parse("8.8.8.8"), IPAddress.Parse("8.8.4.4"), IPAddress.Parse("[2001:4860:4860::8888]"), IPAddress.Parse("[2001:4860:4860::8844]") }),
                new DnsProvider("Quad9", new IPAddress[] { IPAddress.Parse("9.9.9.9"), IPAddress.Parse("[2620:fe::fe]") }),
                new DnsProvider("OpenDNS", new IPAddress[] { IPAddress.Parse("208.67.222.222"), IPAddress.Parse("208.67.220.220"), IPAddress.Parse("[2620:0:ccc::2]"), IPAddress.Parse("[2620:0:ccd::2]") })
            };
        }

        #endregion

        #region public

        public string GetIpv4Addresses()
        {
            string ipv4Addresses = null;

            foreach (IPAddress address in Addresses)
            {
                if (address.AddressFamily == AddressFamily.InterNetwork)
                {
                    if (ipv4Addresses == null)
                        ipv4Addresses = address.ToString();
                    else
                        ipv4Addresses += ", " + address.ToString();
                }
            }

            return ipv4Addresses;
        }

        public string GetIpv6Addresses()
        {
            string ipv6Addresses = null;

            foreach (IPAddress address in Addresses)
            {
                if (address.AddressFamily == AddressFamily.InterNetworkV6)
                {
                    if (ipv6Addresses == null)
                        ipv6Addresses = address.ToString();
                    else
                        ipv6Addresses += ", " + address.ToString();
                }
            }

            return ipv6Addresses;
        }

        public override string ToString()
        {
            return Name;
        }

        public int CompareTo(DnsProvider other)
        {
            return this.Name.CompareTo(other.Name);
        }

        public void WriteTo(BinaryWriter bW)
        {
            bW.WriteShortString(Name);

            bW.Write(Addresses.Count);

            foreach (IPAddress address in Addresses)
                address.WriteTo(bW);
        }

        #endregion
    }
}
