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

        // Immutable snapshot published atomically for lock-free hot-path reads.
        private Snapshot _snapshot;

        #endregion

        #region constructor

        public DnsCookieSecretManager(string secretFilePath)
        {
            if (string.IsNullOrWhiteSpace(secretFilePath))
                throw new ArgumentException("Secret file path must not be null or empty.", nameof(secretFilePath));

            _secretFilePath = secretFilePath;

            lock (_lock)
            {
                Snapshot loaded = LoadLocked();
                if (loaded is null)
                    loaded = GenerateNewSnapshot(previousSecret: null);

                SaveLocked(loaded);
                Volatile.Write(ref _snapshot, loaded);
            }
        }

        #endregion

        #region private

        private Snapshot LoadLocked()
        {
            // Caller must hold _lock
            if (!File.Exists(_secretFilePath))
                return null;

            try
            {
                byte[] data = File.ReadAllBytes(_secretFilePath);
                using MemoryStream ms = new MemoryStream(data, writable: false);
                using BinaryReader br = new BinaryReader(ms);

                int version = br.ReadInt32();
                if (version != FileVersion)
                    throw new InvalidDataException("Unsupported secret file version.");

                DateTime createdUtc = new DateTime(br.ReadInt64(), DateTimeKind.Utc);

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

                return new Snapshot(current, previous, createdUtc);
            }
            catch
            {
                return null;
            }
        }

        private void SaveLocked(Snapshot snapshot)
        {
            // Caller must hold _lock
            if (snapshot is null)
                throw new ArgumentNullException(nameof(snapshot));

            if (snapshot.CurrentSecret is null || snapshot.CurrentSecret.Length < MinSecretLen)
                throw new InvalidOperationException("Current secret is missing or too short.");

            using MemoryStream ms = new MemoryStream();
            using (BinaryWriter bw = new BinaryWriter(ms))
            {
                bw.Write(FileVersion);
                bw.Write(snapshot.CurrentSecretCreatedUtc.Ticks);

                bw.Write(snapshot.CurrentSecret.Length);
                bw.Write(snapshot.CurrentSecret);

                if (snapshot.PreviousSecret is { Length: >= MinSecretLen and <= MaxSecretLen })
                {
                    bw.Write(snapshot.PreviousSecret.Length);
                    bw.Write(snapshot.PreviousSecret);
                }
                else
                {
                    bw.Write(0);
                }
            }

            string directory = Path.GetDirectoryName(_secretFilePath);
            if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
                Directory.CreateDirectory(directory);

            string tmpPath = _secretFilePath + ".tmp";
            File.WriteAllBytes(tmpPath, ms.ToArray());

            // Atomic replace where supported
            if (File.Exists(_secretFilePath))
                File.Replace(tmpPath, _secretFilePath, destinationBackupFileName: null);
            else
                File.Move(tmpPath, _secretFilePath);
        }

        private Snapshot GenerateNewSnapshot(byte[] previousSecret)
        {
            // Caller must hold _lock
            byte[] currentSecret = RandomNumberGenerator.GetBytes(DefaultSecretLen);
            DateTime createdUtc = DateTime.UtcNow;

            // previousSecret is expected to be immutable once published; we pass it through as-is.
            return new Snapshot(currentSecret, previousSecret, createdUtc);
        }

        #endregion

        #region public

        public void Rotate()
        {
            lock (_lock)
            {
                Snapshot currentSnapshot = Volatile.Read(ref _snapshot);

                byte[] previous = currentSnapshot is null ? null : currentSnapshot.CurrentSecret;
                Snapshot nextSnapshot = GenerateNewSnapshot(previous);

                SaveLocked(nextSnapshot);
                Volatile.Write(ref _snapshot, nextSnapshot);
            }
        }

        // Hot path: lock-free, allocation-free. Returned arrays must be treated as read-only by callers.
        public byte[] GetCurrentSecret()
        {
            Snapshot snapshot = Volatile.Read(ref _snapshot);
            return snapshot is null ? null : snapshot.CurrentSecret;
        }

        public byte[] GetPreviousSecret()
        {
            Snapshot snapshot = Volatile.Read(ref _snapshot);
            return snapshot is null ? null : snapshot.PreviousSecret;
        }

        #endregion
        private sealed class Snapshot
        {
            internal readonly byte[] CurrentSecret;
            internal readonly byte[] PreviousSecret; // may be null
            internal readonly DateTime CurrentSecretCreatedUtc;

            internal Snapshot(byte[] currentSecret, byte[] previousSecret, DateTime currentSecretCreatedUtc)
            {
                CurrentSecret = currentSecret;
                PreviousSecret = previousSecret;
                CurrentSecretCreatedUtc = currentSecretCreatedUtc;
            }
        }
    }
}