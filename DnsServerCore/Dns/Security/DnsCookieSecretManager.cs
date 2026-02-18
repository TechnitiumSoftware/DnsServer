/*
Technitium DNS Server
Copyright (C) 2026 Shreyas Zare (shreyas@technitium.com)

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
using System.Security.Cryptography;

namespace DnsServerCore.Dns.Security
{
    public class DnsCookieSecretManager
    {
        #region variables

        readonly string _secretFilePath;
        readonly object _lock = new object();

        byte[] _currentSecret;
        byte[] _previousSecret;
        DateTime _currentSecretCreated;

        #endregion

        #region constructor

        public DnsCookieSecretManager(string secretFilePath)
        {
            _secretFilePath = secretFilePath;
            Load();
        }

        #endregion

        #region private

        private void Load()
        {
            lock (_lock)
            {
                if (File.Exists(_secretFilePath))
                {
                    try
                    {
                        byte[] data = File.ReadAllBytes(_secretFilePath);
                        using (MemoryStream ms = new MemoryStream(data))
                        using (BinaryReader br = new BinaryReader(ms))
                        {
                            int version = br.ReadInt32();
                            if (version == 1)
                            {
                                _currentSecretCreated = new DateTime(br.ReadInt64(), DateTimeKind.Utc);
                                
                                int currentLen = br.ReadInt32();
                                _currentSecret = br.ReadBytes(currentLen);

                                int previousLen = br.ReadInt32();
                                if (previousLen > 0)
                                    _previousSecret = br.ReadBytes(previousLen);
                            }
                        }
                    }
                    catch
                    {
                        // If loading fails, generate new secrets
                        GenerateNewSecrets();
                    }
                }
                else
                {
                    GenerateNewSecrets();
                }
            }
        }

        private void Save()
        {
            lock (_lock)
            {
                using (MemoryStream ms = new MemoryStream())
                {
                    using (BinaryWriter bw = new BinaryWriter(ms))
                    {
                        bw.Write(1); // version
                        bw.Write(_currentSecretCreated.Ticks);
                        
                        bw.Write(_currentSecret.Length);
                        bw.Write(_currentSecret);

                        if (_previousSecret != null)
                        {
                            bw.Write(_previousSecret.Length);
                            bw.Write(_previousSecret);
                        }
                        else
                        {
                            bw.Write(0);
                        }
                    }

                    string directory = Path.GetDirectoryName(_secretFilePath);
                    if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
                        Directory.CreateDirectory(directory);

                    File.WriteAllBytes(_secretFilePath, ms.ToArray());
                }
            }
        }

        private void GenerateNewSecrets()
        {
            _currentSecret = RandomNumberGenerator.GetBytes(32);
            _currentSecretCreated = DateTime.UtcNow;
            _previousSecret = null;
            Save();
        }

        #endregion

        #region public

        public void Rotate()
        {
            lock (_lock)
            {
                _previousSecret = _currentSecret;
                _currentSecret = RandomNumberGenerator.GetBytes(32);
                _currentSecretCreated = DateTime.UtcNow;
                Save();
            }
        }

        public byte[] GetCurrentSecret()
        {
            lock (_lock)
            {
                return _currentSecret;
            }
        }

        public byte[] GetPreviousSecret()
        {
            lock (_lock)
            {
                return _previousSecret;
            }
        }

        #endregion
    }
}
