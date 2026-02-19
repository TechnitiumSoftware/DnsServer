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
using System.Threading;

namespace DnsServerCore.Dns.Security
{
    public class DnsCookieSecretManager
    {
        #region constants

        private const int FileVersion = 1;

        // Operational bounds; keep aligned with validator policy.
        private const int MinSecretLen = 16;
        private const int MaxSecretLen = 256;

        // Default secret size (256-bit)
        private const int DefaultSecretLen = 32;

        #endregion

        #region variables

        readonly string _secretFilePath;
        readonly Lock _lock = new Lock();

        byte[] _currentSecret;
        byte[] _previousSecret;
        DateTime _currentSecretCreated;

        #endregion

        #region constructor

        public DnsCookieSecretManager(string secretFilePath)
        {
            if (string.IsNullOrWhiteSpace(secretFilePath))
                throw new ArgumentException("Secret file path must not be null or empty.", nameof(secretFilePath));

            _secretFilePath = secretFilePath;

            lock (_lock)
            {
                LoadLocked();
            }
        }

        #endregion

        #region private

        private void LoadLocked()
        {
            // Caller must hold _lock
            if (!File.Exists(_secretFilePath))
            {
                GenerateNewSecretsLocked();
                return;
            }

            try
            {
                byte[] data = File.ReadAllBytes(_secretFilePath);
                using MemoryStream ms = new MemoryStream(data, writable: false);
                using BinaryReader br = new BinaryReader(ms);

                int version = br.ReadInt32();
                if (version != FileVersion)
                    throw new InvalidDataException("Unsupported secret file version.");

                _currentSecretCreated = new DateTime(br.ReadInt64(), DateTimeKind.Utc);

                int currentLen = br.ReadInt32();
                if (currentLen < MinSecretLen || currentLen > MaxSecretLen)
                    throw new InvalidDataException("Invalid current secret length.");

                byte[] current = br.ReadBytes(currentLen);
                if (current.Length != currentLen)
                    throw new EndOfStreamException("Unexpected end of secret file (current secret).");

                int previousLen = br.ReadInt32();
                byte[] previous = null;

                if (previousLen != 0)
                {
                    if (previousLen < MinSecretLen || previousLen > MaxSecretLen)
                        throw new InvalidDataException("Invalid previous secret length.");

                    previous = br.ReadBytes(previousLen);
                    if (previous.Length != previousLen)
                        throw new EndOfStreamException("Unexpected end of secret file (previous secret).");
                }

                _currentSecret = current;
                _previousSecret = previous;
            }
            catch
            {
                GenerateNewSecretsLocked();
            }
        }

        private void SaveLocked()
        {
            // Caller must hold _lock
            if (_currentSecret is null || _currentSecret.Length < MinSecretLen)
                throw new InvalidOperationException("Current secret is missing or too short.");

            using MemoryStream ms = new MemoryStream();
            using (BinaryWriter bw = new BinaryWriter(ms))
            {
                bw.Write(FileVersion);
                bw.Write(_currentSecretCreated.Ticks);

                bw.Write(_currentSecret.Length);
                bw.Write(_currentSecret);

                if (_previousSecret is { Length: >= MinSecretLen and <= MaxSecretLen })
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

        private void GenerateNewSecretsLocked()
        {
            // Caller must hold _lock
            _currentSecret = RandomNumberGenerator.GetBytes(DefaultSecretLen);
            _currentSecretCreated = DateTime.UtcNow;
            _previousSecret = null;

            SaveLocked();
        }

        #endregion

        #region public

        public void Rotate()
        {
            lock (_lock)
            {
                _previousSecret = _currentSecret is null ? null : (byte[])_currentSecret.Clone();
                _currentSecret = RandomNumberGenerator.GetBytes(DefaultSecretLen);
                _currentSecretCreated = DateTime.UtcNow;

                SaveLocked();
            }
        }

        // Returning spans here is unsafe once the lock is released; return a clone instead.
        public byte[] GetCurrentSecret()
        {
            lock (_lock)
            {
                return _currentSecret is null ? null : (byte[])_currentSecret.Clone();
            }
        }

        public byte[] GetPreviousSecret()
        {
            lock (_lock)
            {
                return _previousSecret is null ? null : (byte[])_previousSecret.Clone();
            }
        }

        #endregion
    }
}
