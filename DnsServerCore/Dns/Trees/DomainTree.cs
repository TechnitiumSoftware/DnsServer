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
using System.Text;
using TechnitiumLibrary.ByteTree;

namespace DnsServerCore.Dns.Trees
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
            _reverseKeyMap = new byte[41];

            int keyCode;

            for (int i = 0; i < _keyMap.Length; i++)
            {
                if (i == 46) //[.]
                {
                    keyCode = 0;
                    _keyMap[i] = (byte)keyCode;
                    _reverseKeyMap[keyCode] = (byte)i;
                }
                else if (i == 42) //[*]
                {
                    keyCode = 1;
                    _keyMap[i] = 0xff; //skipped value for optimization
                    _reverseKeyMap[keyCode] = (byte)i;
                }
                else if (i == 45) //[-]
                {
                    keyCode = 2;
                    _keyMap[i] = (byte)keyCode;
                    _reverseKeyMap[keyCode] = (byte)i;
                }
                else if (i == 47) //[/]
                {
                    keyCode = 3;
                    _keyMap[i] = (byte)keyCode;
                    _reverseKeyMap[keyCode] = (byte)i;
                }
                else if ((i >= 48) && (i <= 57)) //[0-9]
                {
                    keyCode = i - 44; //4 - 13
                    _keyMap[i] = (byte)keyCode;
                    _reverseKeyMap[keyCode] = (byte)i;
                }
                else if (i == 95) //[_]
                {
                    keyCode = 14;
                    _keyMap[i] = (byte)keyCode;
                    _reverseKeyMap[keyCode] = (byte)i;
                }
                else if ((i >= 97) && (i <= 122)) //[a-z]
                {
                    keyCode = i - 82; //15 - 40
                    _keyMap[i] = (byte)keyCode;
                    _reverseKeyMap[keyCode] = (byte)i;
                }
                else if ((i >= 65) && (i <= 90)) //[A-Z]
                {
                    keyCode = i - 50; //15 - 40
                    _keyMap[i] = (byte)keyCode;
                }
                else
                {
                    _keyMap[i] = 0xff;
                }
            }
        }

        public DomainTree()
            : base(41)
        { }

        #endregion

        #region protected

        protected override byte[] ConvertToByteKey(string domain, bool throwException = true)
        {
            if (domain.Length == 0)
                return [];

            if (domain.Length > 255)
            {
                if (throwException)
                    throw new InvalidDomainNameException("Invalid domain name [" + domain + "]: length cannot exceed 255 bytes.");

                return null;
            }

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
                {
                    if (throwException)
                        throw new InvalidDomainNameException("Invalid domain name [" + domain + "]: label length cannot be 0 byte.");

                    return null;
                }

                if (labelLength > 63)
                {
                    if (throwException)
                        throw new InvalidDomainNameException("Invalid domain name [" + domain + "]: label length cannot exceed 63 bytes.");

                    return null;
                }

                if (domain[labelStart + 1] == '-')
                {
                    if (throwException)
                        throw new InvalidDomainNameException("Invalid domain name [" + domain + "]: label cannot start with hyphen.");

                    return null;
                }

                if (domain[labelEnd] == '-')
                {
                    if (throwException)
                        throw new InvalidDomainNameException("Invalid domain name [" + domain + "]: label cannot end with hyphen.");

                    return null;
                }

                if ((labelLength == 1) && (domain[labelStart + 1] == '*')) //[*]
                {
                    key[keyOffset++] = 1;
                }
                else
                {
                    for (i = labelStart + 1; i <= labelEnd; i++)
                    {
                        labelChar = domain[i];
                        if (labelChar >= _keyMap.Length)
                        {
                            if (throwException)
                                throw new InvalidDomainNameException("Invalid domain name [" + domain + "]: invalid character [" + labelChar + "] was found.");

                            return null;
                        }

                        labelKeyCode = _keyMap[labelChar];
                        if (labelKeyCode == 0xff)
                        {
                            if (throwException)
                                throw new InvalidDomainNameException("Invalid domain name [" + domain + "]: invalid character [" + labelChar + "] was found.");

                            return null;
                        }

                        key[keyOffset++] = labelKeyCode;
                    }
                }

                key[keyOffset++] = 0; //[.]
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

            Span<byte> domain = stackalloc byte[length];
            int i;
            int k;

            for (i = 0; i < domain.Length; i++)
            {
                k = key[i + startIndex];
                if (k == 0) //[.]
                    break;

                domain[i] = _reverseKeyMap[k];
            }

            return Encoding.ASCII.GetString(domain.Slice(0, i));
        }

        #endregion

        #region public

        public override bool TryRemove(string key, out T value)
        {
            if (TryRemove(key, out value, out Node currentNode))
            {
                currentNode.CleanThisBranch();
                return true;
            }

            return false;
        }

        #endregion
    }
}
