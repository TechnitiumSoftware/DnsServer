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
                {
                    loaded = new Snapshot(GenerateSecret(), staging: null, DateTime.UtcNow);
                    SaveLocked(loaded);
                }

                Volatile.Write(ref _snapshot, loaded);
            }
        }

        #endregion

        #region private

        private Snapshot LoadLocked()
        {
            // Caller must hold _lock
            return LoadFileLocked(_secretFilePath);
        }

        private static Snapshot LoadFileLocked(string path)
        {
            try
            {
                using FileStream stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
                using BinaryReader br = new BinaryReader(stream);

                int version = br.ReadInt32();
                if (version != FileVersion)
                    throw new InvalidDataException($"Unsupported DNS Cookie secret state version: {version}.");

                long createdUtcTicks = br.ReadInt64();
                if (createdUtcTicks < DateTime.MinValue.Ticks || createdUtcTicks > DateTime.MaxValue.Ticks)
                    throw new InvalidDataException("Invalid DNS Cookie secret creation timestamp.");

                DateTime createdUtc = new DateTime(createdUtcTicks, DateTimeKind.Utc);

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

                if (stream.Position != stream.Length)
                    throw new InvalidDataException("Unexpected trailing data in DNS Cookie secret state.");

                return new Snapshot(active, staging, createdUtc);
            }
            catch (FileNotFoundException)
            {
                return null;
            }
            catch (DirectoryNotFoundException)
            {
                return null;
            }
            catch (InvalidDataException ex)
            {
                throw new InvalidDataException($"DNS Cookie secret state file '{path}' is malformed; the existing file was preserved.", ex);
            }
            catch (EndOfStreamException ex)
            {
                throw new InvalidDataException($"DNS Cookie secret state file '{path}' is truncated; the existing file was preserved.", ex);
            }
            catch (IOException ex)
            {
                throw new IOException($"Failed to read existing DNS Cookie secret state file '{path}'; the existing file was preserved.", ex);
            }
            catch (UnauthorizedAccessException ex)
            {
                throw new UnauthorizedAccessException($"Permission denied reading existing DNS Cookie secret state file '{path}'; the existing file was preserved.", ex);
            }
        }

        internal static bool TryGetStatus(string path, out string activeId, out string stagingId, out DateTime activeCreatedUtc)
        {
            Snapshot snapshot = LoadFileLocked(path);
            if (snapshot is null)
            {
                activeId = null;
                stagingId = null;
                activeCreatedUtc = default;
                return false;
            }

            GetStatus(snapshot, out activeId, out stagingId, out activeCreatedUtc);
            return true;
        }

        private static void GetStatus(Snapshot snapshot, out string activeId, out string stagingId, out DateTime activeCreatedUtc)
        {
            activeId = Convert.ToHexString(SHA256.HashData(snapshot.Active));
            stagingId = snapshot.Staging is null ? null : Convert.ToHexString(SHA256.HashData(snapshot.Staging));
            activeCreatedUtc = snapshot.ActiveCreatedUtc;
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

        // Automatic state transition:
        //   active-only -> new active + old active as staging
        //   active + staging -> unchanged (manual staging always wins)
        // The return value lets the timer distinguish a completed rotation from a
        // deliberate skip. Persistence happens before the new snapshot is published.
        public bool Rotate()
        {
            lock (_lock)
            {
                Snapshot current = Volatile.Read(ref _snapshot);
                if (current.Staging is not null)
                    return false;

                Snapshot nextSnapshot = new Snapshot(GenerateSecret(), current.Active, DateTime.UtcNow);

                SaveLocked(nextSnapshot);
                Volatile.Write(ref _snapshot, nextSnapshot);
                return true;
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

        public DateTime ActiveCreatedUtc
        {
            get { return Volatile.Read(ref _snapshot).ActiveCreatedUtc; }
        }

        public string ActiveId
        {
            get { return Convert.ToHexString(SHA256.HashData(Volatile.Read(ref _snapshot).Active)); }
        }

        public string StagingId
        {
            get
            {
                byte[] staging = Volatile.Read(ref _snapshot).Staging;
                return staging is null ? null : Convert.ToHexString(SHA256.HashData(staging));
            }
        }

        internal void GetStatus(out string activeId, out string stagingId, out DateTime activeCreatedUtc)
        {
            GetStatus(Volatile.Read(ref _snapshot), out activeId, out stagingId, out activeCreatedUtc);
        }

        public void AddStaging()
        {
            lock (_lock)
            {
                Snapshot current = Volatile.Read(ref _snapshot);
                if (current.Staging is not null)
                    throw new InvalidOperationException("There is already a staging secret.");

                // Manual transition: active-only -> same active + new staging.
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

                // Manual transition: active + staging -> staging active + old active staging.
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

                // Manual transition: active + staging -> same active only.
                Snapshot next = new Snapshot(current.Active, null, current.ActiveCreatedUtc);
                SaveLocked(next);
                Volatile.Write(ref _snapshot, next);
            }
        }

        public void Import(Stream stream)
        {
            if (stream is null)
                throw new ArgumentNullException(nameof(stream));

            using MemoryStream buffer = new MemoryStream();
            stream.CopyTo(buffer);

            lock (_lock)
            {
                string tmpPath = _secretFilePath + ".tmp";
                WriteSecretFile(tmpPath, buffer.ToArray());
                Snapshot imported;
                try
                {
                    imported = LoadFileLocked(tmpPath);
                    if (imported is null)
                        throw new InvalidDataException("Imported DNS Cookie secret state is missing.");
                }
                catch
                {
                    File.Delete(tmpPath);
                    throw;
                }

                if (File.Exists(_secretFilePath))
                    File.Replace(tmpPath, _secretFilePath, destinationBackupFileName: null);
                else
                    File.Move(tmpPath, _secretFilePath);

                RestrictSecretFilePermissions(_secretFilePath);
                Volatile.Write(ref _snapshot, imported);
            }
        }

        // Cluster export takes the same lock as every transition so the bytes always
        // describe one complete, persisted state.
        internal void Export(Stream stream)
        {
            if (stream is null)
                throw new ArgumentNullException(nameof(stream));

            lock (_lock)
            {
                using FileStream file = new FileStream(_secretFilePath, FileMode.Open, FileAccess.Read, FileShare.Read);
                file.CopyTo(stream);
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
