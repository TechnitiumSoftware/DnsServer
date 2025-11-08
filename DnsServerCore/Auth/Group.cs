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
using System.IO;
using TechnitiumLibrary.IO;

namespace DnsServerCore.Auth
{
    class Group : IComparable<Group>
    {
        #region variables

        public const string ADMINISTRATORS = "Administrators";
        public const string EVERYONE = "Everyone";
        public const string DNS_ADMINISTRATORS = "DNS Administrators";
        public const string DHCP_ADMINISTRATORS = "DHCP Administrators";

        string _name;
        string _description;

        #endregion

        #region constructor

        public Group(string name, string description)
        {
            Name = name;
            Description = description;
        }

        public Group(BinaryReader bR)
        {
            switch (bR.ReadByte())
            {
                case 1:
                    _name = bR.ReadShortString();
                    _description = bR.ReadShortString();
                    break;

                default:
                    throw new InvalidDataException("Invalid data or version not supported.");
            }
        }

        #endregion

        #region public

        public void WriteTo(BinaryWriter bW)
        {
            bW.Write((byte)1);
            bW.WriteShortString(_name);
            bW.WriteShortString(_description);
        }

        public override bool Equals(object obj)
        {
            if (obj is not Group other)
                return false;

            return _name.Equals(other._name, StringComparison.OrdinalIgnoreCase);
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(_name);
        }

        public override string ToString()
        {
            return _name;
        }

        public int CompareTo(Group other)
        {
            return _name.CompareTo(other._name);
        }

        #endregion

        #region properties

        public string Name
        {
            get { return _name; }
            set
            {
                if (string.IsNullOrWhiteSpace(value))
                    throw new ArgumentException("Group name cannot be null or empty.", nameof(Name));

                if (value.Length > 255)
                    throw new ArgumentException("Group name length cannot exceed 255 characters.", nameof(Name));

                switch (_name?.ToLowerInvariant())
                {
                    case "everyone":
                    case "administrators":
                    case "dns administrators":
                    case "dhcp administrators":
                        throw new InvalidOperationException("Access was denied.");

                    default:
                        _name = value;
                        break;
                }
            }
        }

        public string Description
        {
            get { return _description; }
            set
            {
                if (string.IsNullOrWhiteSpace(value))
                    _description = "";
                else if (value.Length > 255)
                    throw new ArgumentException("Group description length cannot exceed 255 characters.", nameof(Description));
                else
                    _description = value;
            }
        }

        #endregion
    }
}
