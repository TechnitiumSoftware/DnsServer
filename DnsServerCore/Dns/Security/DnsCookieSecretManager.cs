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
                    loaded = new Snapshot(GenerateSecret(), staging: null, DateTime.UtcNow);

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

                byte[] active = br.ReadBytes(currentLen);
                if (active.Length != currentLen)
                    throw new EndOfStreamException("Unexpected end of secret file (active secret).");

                int previousLen = br.ReadInt32();
                byte[] staging = null;

                if (previousLen != 0)
                {
                    if (previousLen < MinSecretLen || previousLen > MaxSecretLen)
                        throw new InvalidDataException("Invalid previous secret length.");

                    staging = br.ReadBytes(previousLen);
                    if (staging.Length != previousLen)
                        throw new EndOfStreamException("Unexpected end of secret file (staging secret).");
                }

                return new Snapshot(active, staging, createdUtc);
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

            if (snapshot.Active is null || snapshot.Active.Length < MinSecretLen)
                throw new InvalidOperationException("Active secret is missing or too short.");

            using MemoryStream ms = new MemoryStream();
            using (BinaryWriter bw = new BinaryWriter(ms))
            {
                bw.Write(FileVersion);
                bw.Write(snapshot.ActiveCreatedUtc.Ticks);

                bw.Write(snapshot.Active.Length);
                bw.Write(snapshot.Active);

                if (snapshot.Staging is { Length: >= MinSecretLen and <= MaxSecretLen })
                {
                    bw.Write(snapshot.Staging.Length);
                    bw.Write(snapshot.Staging);
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
            WriteSecretFile(tmpPath, ms.ToArray());

            // Atomic replace where supported
            if (File.Exists(_secretFilePath))
                File.Replace(tmpPath, _secretFilePath, destinationBackupFileName: null);
            else
                File.Move(tmpPath, _secretFilePath);

            RestrictSecretFilePermissions(_secretFilePath);
        }

        private static void WriteSecretFile(string path, byte[] contents)
        {
            if (OperatingSystem.IsWindows())
            {
                File.WriteAllBytes(path, contents);
                return;
            }
            FileStreamOptions options = new FileStreamOptions
            {
                Mode = FileMode.Create,
                Access = FileAccess.Write,
                Share = FileShare.None,
                UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite
            };
            using FileStream stream = new FileStream(path, options);
            stream.Write(contents, 0, contents.Length);
        }
        private static void RestrictSecretFilePermissions(string path)
        {
            if (!OperatingSystem.IsWindows() && File.Exists(path))
                File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }

        private static byte[] GenerateSecret()
        {
            return RandomNumberGenerator.GetBytes(DefaultSecretLen);
        }

        #endregion

        #region public

        public void Rotate()
        {
            lock (_lock)
            {
                Snapshot current = Volatile.Read(ref _snapshot);
                Snapshot nextSnapshot = new Snapshot(GenerateSecret(), current.Active, DateTime.UtcNow);

                SaveLocked(nextSnapshot);
                Volatile.Write(ref _snapshot, nextSnapshot);
            }
        }

        // Hot path: lock-free, allocation-free. Returned arrays must be treated as read-only by callers.
        public byte[] Active
        {
            get { return Volatile.Read(ref _snapshot)?.Active; }
        }

        public byte[] Staging
        {
            get { return Volatile.Read(ref _snapshot)?.Staging; }
        }

        public void AddStaging()
        {
            lock (_lock)
            {
                Snapshot current = Volatile.Read(ref _snapshot);
                Snapshot next = new Snapshot(current.Active, GenerateSecret(), current.ActiveCreatedUtc);
                SaveLocked(next);
                Volatile.Write(ref _snapshot, next);
            }
        }

        public void ActivateStaging()
        {
            lock (_lock)
            {
                Snapshot current = Volatile.Read(ref _snapshot);
                if (current.Staging is null)
                    throw new InvalidOperationException("There is no staging secret to activate.");

                Snapshot next = new Snapshot(current.Staging, current.Active, DateTime.UtcNow);
                SaveLocked(next);
                Volatile.Write(ref _snapshot, next);
            }
        }

        public void DropStaging()
        {
            lock (_lock)
            {
                Snapshot current = Volatile.Read(ref _snapshot);
                if (current.Staging is null)
                    return;

                Snapshot next = new Snapshot(current.Active, null, current.ActiveCreatedUtc);
                SaveLocked(next);
                Volatile.Write(ref _snapshot, next);
            }
        }

        #endregion
        private sealed class Snapshot
        {
            internal readonly byte[] Active;
            internal readonly byte[] Staging; // may be null
            internal readonly DateTime ActiveCreatedUtc;

            internal Snapshot(byte[] active, byte[] staging, DateTime activeCreatedUtc)
            {
                Active = active;
                Staging = staging;
                ActiveCreatedUtc = activeCreatedUtc;
            }
        }
    }
}
