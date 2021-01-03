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
using System.Text;
using TechnitiumLibrary.ByteTree;

namespace DnsServerCore.Dns.Zones
{
    class DomainTree<T> : ByteTree<string, T> where T : class
    {
        #region variables

        readonly static byte[] _keyMap;
        readonly static byte[] _reverseKeyMap;

        #endregion

        #region constructor

        static DomainTree()
        {
            _keyMap = new byte[256];
            _reverseKeyMap = new byte[40];

            for (int i = 0; i < _keyMap.Length; i++)
            {
                if ((i >= 97) && (i <= 122)) //[a-z]
                {
                    _keyMap[i] = (byte)(i - 97);
                    _reverseKeyMap[_keyMap[i]] = (byte)i;
                }
                else if ((i >= 65) && (i <= 90)) //[a-z]
                {
                    _keyMap[i] = (byte)(i - 65);
                    _reverseKeyMap[_keyMap[i]] = (byte)i;
                }
                else if ((i >= 48) && (i <= 57)) //[0-9]
                {
                    _keyMap[i] = (byte)(26 + i - 48);
                    _reverseKeyMap[_keyMap[i]] = (byte)i;
                }
                else if (i == 45) //[-]
                {
                    _keyMap[i] = 36;
                    _reverseKeyMap[36] = 45;
                }
                else if (i == 95) //[_]
                {
                    _keyMap[i] = 37;
                    _reverseKeyMap[37] = 95;
                }
                else if (i == 42) //[*]
                {
                    _keyMap[i] = 0xff; //skipped value 38 for optimization
                    _reverseKeyMap[38] = 42;
                }
                else if (i == 46) //[.]
                {
                    _keyMap[i] = 39;
                    _reverseKeyMap[39] = 46;
                }
                else
                {
                    _keyMap[i] = 0xff;
                }
            }
        }

        public DomainTree()
            : base(40)
        { }

        #endregion

        #region protected

        protected override byte[] ConvertToByteKey(string domain)
        {
            if (domain.Length == 0)
                return Array.Empty<byte>();

            if (domain.Length > 255)
                throw new InvalidDomainNameException("Invalid domain name [" + domain + "]: length cannot exceed 255 bytes.");

            byte[] key = new byte[domain.Length + 1];
            int keyOffset = 0;
            int labelStart;
            int labelEnd = domain.Length - 1;
            int labelLength;
            int labelChar;
            byte labelKeyCode;
            int i;

            do
            {
                if (labelEnd < 0)
                    labelEnd = 0;

                labelStart = domain.LastIndexOf('.', labelEnd);
                labelLength = labelEnd - labelStart;

                if (labelLength == 0)
                    throw new InvalidDomainNameException("Invalid domain name [" + domain + "]: label length cannot be 0 byte.");

                if (labelLength > 63)
                    throw new InvalidDomainNameException("Invalid domain name [" + domain + "]: label length cannot exceed 63 bytes.");

                if (domain[labelStart + 1] == '-')
                    throw new InvalidDomainNameException("Invalid domain name [" + domain + "]: label cannot start with hyphen.");

                if (domain[labelEnd] == '-')
                    throw new InvalidDomainNameException("Invalid domain name [" + domain + "]: label cannot end with hyphen.");

                if ((labelLength == 1) && (domain[labelStart + 1] == '*'))
                {
                    key[keyOffset++] = 38;
                }
                else
                {
                    for (i = labelStart + 1; i <= labelEnd; i++)
                    {
                        labelChar = domain[i];
                        if (labelChar >= _keyMap.Length)
                            throw new InvalidDomainNameException("Invalid domain name [" + domain + "]: invalid character [" + labelChar + "] was found.");

                        labelKeyCode = _keyMap[labelChar];
                        if (labelKeyCode == 0xff)
                            throw new InvalidDomainNameException("Invalid domain name [" + domain + "]: invalid character [" + labelChar + "] was found.");

                        key[keyOffset++] = labelKeyCode;
                    }
                }

                key[keyOffset++] = 39;
                labelEnd = labelStart - 1;
            }
            while (labelStart > -1);

            return key;
        }

        protected static string ConvertKeyToLabel(byte[] key, int startIndex)
        {
            int length = key.Length - startIndex;
            if (length < 1)
                return null;

            byte[] domain = new byte[length];
            int i;
            int k;

            for (i = 0; i < domain.Length; i++)
            {
                k = key[i + startIndex];
                if (k == 39)
                    break;

                domain[i] = _reverseKeyMap[k];
            }

            return Encoding.ASCII.GetString(domain, 0, i);
        }

        #endregion

        #region public

        public override bool TryRemove(string key, out T value)
        {
            if (TryRemove(key, out value, out Node closestNode))
            {
                closestNode.CleanThisBranch();
                return true;
            }

            return false;
        }

        #endregion
    }
}
