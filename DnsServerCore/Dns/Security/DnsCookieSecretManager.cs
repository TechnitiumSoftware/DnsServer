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

        private const int LegacyFileVersion = 1;
        private const int CurrentFileVersion = 2;

        // Operational bounds; keep aligned with validator policy.
        private const int MinSecretLen = 16;
        private const int MaxSecretLen = 256;

        // Serialized state contains versioned timestamps and length fields for the
        // active, previous-validation, and manually staged secrets.
        private const int SerializedMetadataSize = sizeof(int) + (2 * sizeof(long)) + (3 * sizeof(int));
        internal const int MaxSerializedStateSize = SerializedMetadataSize + (3 * MaxSecretLen);

        private static readonly TimeSpan PreviousKeyValidationOverlap =
            TimeSpan.FromHours(1) + TimeSpan.FromMinutes(5) + TimeSpan.FromMinutes(5);

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
                    loaded = new Snapshot(CurrentFileVersion, GenerateSecret(), DateTime.UtcNow, null, null, null);
                    SaveLocked(loaded);
                }
                else if (loaded.FormatVersion != CurrentFileVersion)
                {
                    loaded = new Snapshot(CurrentFileVersion, loaded.Active, loaded.ActiveCreatedUtc,
                        null, null, loaded.StagedNext);
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
                if (stream.Length > MaxSerializedStateSize)
                    throw new InvalidDataException($"DNS Cookie secret state exceeds the maximum size of {MaxSerializedStateSize} bytes.");
                using BinaryReader br = new BinaryReader(stream);

                int version = br.ReadInt32();
                if (version < LegacyFileVersion || version > CurrentFileVersion)
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

                if (version == LegacyFileVersion)
                {
                    byte[] staging = ReadOptionalSecret(br, "staging");
                    EnsureEndOfFile(stream);
                    return new Snapshot(version, active, createdUtc, null, null, staging);
                }

                long retirementTicks = br.ReadInt64();
                byte[] previous = ReadOptionalSecret(br, "previous");
                DateTime? previousRetireUtc = null;
                if (previous is not null)
                {
                    if (retirementTicks < DateTime.MinValue.Ticks || retirementTicks > DateTime.MaxValue.Ticks)
                        throw new InvalidDataException("Invalid previous secret retirement timestamp.");
                    previousRetireUtc = new DateTime(retirementTicks, DateTimeKind.Utc);
                    if (createdUtc.Ticks > DateTime.MaxValue.Ticks - PreviousKeyValidationOverlap.Ticks ||
                        previousRetireUtc != createdUtc + PreviousKeyValidationOverlap)
                        throw new InvalidDataException("Previous secret retirement timestamp does not match the validation horizon.");
                }
                else if (retirementTicks != 0)
                    throw new InvalidDataException("A retirement timestamp exists without a previous secret.");

                byte[] stagedNext = ReadOptionalSecret(br, "staged next");
                EnsureEndOfFile(stream);
                return new Snapshot(version, active, createdUtc, previous, previousRetireUtc, stagedNext);
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

        private static byte[] ReadOptionalSecret(BinaryReader reader, string name)
        {
            int length = reader.ReadInt32();
            if (length == 0)
                return null;
            if (length < MinSecretLen || length > MaxSecretLen)
                throw new InvalidDataException($"Invalid {name} secret length.");
            byte[] value = reader.ReadBytes(length);
            if (value.Length != length)
                throw new EndOfStreamException($"Unexpected end of secret file ({name} secret).");
            return value;
        }

        private static void EnsureEndOfFile(Stream stream)
        {
            if (stream.Position != stream.Length)
                throw new InvalidDataException("Unexpected trailing data in DNS Cookie secret state.");
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
            stagingId = snapshot.StagedNext is null ? null : Convert.ToHexString(SHA256.HashData(snapshot.StagedNext));
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
                bw.Write(CurrentFileVersion);
                bw.Write(snapshot.ActiveCreatedUtc.Ticks);

                bw.Write(snapshot.Active.Length);
                bw.Write(snapshot.Active);

                bw.Write(snapshot.PreviousRetireUtc?.Ticks ?? 0);
                WriteOptionalSecret(bw, snapshot.Previous, "previous");
                WriteOptionalSecret(bw, snapshot.StagedNext, "staged next");
            }

            if (ms.Length > MaxSerializedStateSize)
                throw new InvalidOperationException("DNS Cookie secret state exceeds its maximum serialized size.");

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

        private static void WriteOptionalSecret(BinaryWriter writer, byte[] secret, string name)
        {
            if (secret is null)
            {
                writer.Write(0);
                return;
            }
            if (secret.Length < MinSecretLen || secret.Length > MaxSecretLen)
                throw new InvalidOperationException($"The {name} secret has an invalid length.");
            writer.Write(secret.Length);
            writer.Write(secret);
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

        // Retire an expired validation-only key before starting the next rotation.
        // Manual staging is independent and survives either automatic transition.
        public bool Rotate()
        {
            lock (_lock)
            {
                Snapshot current = Volatile.Read(ref _snapshot);
                DateTime now = DateTime.UtcNow;
                Snapshot nextSnapshot;

                if (current.Previous is not null)
                {
                    if (now < current.PreviousRetireUtc.Value)
                        return false;
                    nextSnapshot = new Snapshot(CurrentFileVersion, current.Active, current.ActiveCreatedUtc,
                        null, null, current.StagedNext);
                }
                else
                {
                    nextSnapshot = new Snapshot(CurrentFileVersion, GenerateSecret(), now,
                        current.Active, now + PreviousKeyValidationOverlap, current.StagedNext);
                }

                SaveLocked(nextSnapshot);
                Volatile.Write(ref _snapshot, nextSnapshot);
                return true;
            }
        }

        // Management-facing copies prevent callers from mutating published secret material.
        public byte[] Active
        {
            get
            {
                byte[] active = Volatile.Read(ref _snapshot)?.Active;
                return active is null ? null : (byte[])active.Clone();
            }
        }

        public byte[] Staging
        {
            get
            {
                byte[] staging = Volatile.Read(ref _snapshot)?.StagedNext;
                return staging is null ? null : (byte[])staging.Clone();
            }
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
                byte[] staging = Volatile.Read(ref _snapshot).StagedNext;
                return staging is null ? null : Convert.ToHexString(SHA256.HashData(staging));
            }
        }

        internal void GetStatus(out string activeId, out string stagingId, out DateTime activeCreatedUtc)
        {
            GetStatus(Volatile.Read(ref _snapshot), out activeId, out stagingId, out activeCreatedUtc);
        }

        internal DateTime GetNextTransitionUtc(TimeSpan rotationPeriod)
        {
            Snapshot snapshot = Volatile.Read(ref _snapshot);
            return snapshot.PreviousRetireUtc ?? snapshot.ActiveCreatedUtc + rotationPeriod;
        }

        internal void GetSecrets(out byte[] active, out byte[] staging, out byte[] previous)
        {
            Snapshot snapshot = Volatile.Read(ref _snapshot);
            active = snapshot.Active;
            staging = snapshot.StagedNext;
            previous = snapshot.Previous;
        }

        /// <summary>
        /// Stages a new secret for activation. Part of RFC 9018 §5 three-stage anycast rollout.
        ///
        /// Three-stage rotation ensures zero-downtime secret transition in anycast clusters:
        /// 1. Stage (add staging secret) - new key exists but is not yet used for validation
        /// 2. Wait - clients and caches expire with old key (wait ≥ longest zone TTL + 1 hour)
        /// 3. Activate (promote staging to active) - all replicas now validate against new key
        ///
        /// Throws InvalidOperationException if a staging secret already exists.
        /// See RFC 9018 §5 and APIDOCS.md DNS Cookie section for operational guidance.
        /// </summary>
        public void AddStaging()
        {
            lock (_lock)
            {
                Snapshot current = Volatile.Read(ref _snapshot);
                if (current.StagedNext is not null)
                    throw new InvalidOperationException("There is already a staging secret.");

                // Manual transition: active-only -> same active + new staging.
                Snapshot next = new Snapshot(CurrentFileVersion, current.Active, current.ActiveCreatedUtc,
                    current.Previous, current.PreviousRetireUtc, GenerateSecret());
                SaveLocked(next);
                Volatile.Write(ref _snapshot, next);
            }
        }

        /// <summary>
        /// Activates the staged secret and makes it the new active secret (stage 3 of RFC 9018 §5).
        ///
        /// Prevents activation until the previous secret's validation window has expired.
        /// This ensures all clients that were validated against the old key have their
        /// cached server cookies expire (timestamp window closes) before the old secret is retired.
        ///
        /// After activation, the old active secret becomes the staging secret (retained for ~70 minutes).
        /// Throws InvalidOperationException if:
        /// - No staging secret exists, or
        /// - Previous secret's validation window has not yet expired (too soon)
        ///
        /// See RFC 9018 §4.3 (timestamp validation window), §5 (anycast coordination), and
        /// APIDOCS.md DNS Cookie section for complete operational guidance.
        /// </summary>
        public void ActivateStaging()
        {
            lock (_lock)
            {
                Snapshot current = Volatile.Read(ref _snapshot);
                if (current.StagedNext is null)
                    throw new InvalidOperationException("There is no staging secret to activate.");

                DateTime now = DateTime.UtcNow;
                if (current.Previous is not null && now < current.PreviousRetireUtc.Value)
                    throw new InvalidOperationException("The staging secret cannot be activated until the previous secret validation window has ended.");

                Snapshot next = new Snapshot(CurrentFileVersion, current.StagedNext, now,
                    current.Active, now + PreviousKeyValidationOverlap, null);
                SaveLocked(next);
                Volatile.Write(ref _snapshot, next);
            }
        }

        /// <summary>
        /// Drops the staged secret without activating it. Call this to abort a staged transition.
        ///
        /// This is used when a staged secret transition is no longer needed (e.g., if key rotation
        /// was postponed or cancelled). Operators should consult RFC 9018 §5 and APIDOCS.md
        /// DNS Cookie section when making manual secret management decisions.
        /// </summary>
        public void DropStaging()
        {
            lock (_lock)
            {
                Snapshot current = Volatile.Read(ref _snapshot);
                if (current.StagedNext is null)
                    return;

                // Manual transition: active + staging -> same active only.
                Snapshot next = new Snapshot(CurrentFileVersion, current.Active, current.ActiveCreatedUtc,
                    current.Previous, current.PreviousRetireUtc, null);
                SaveLocked(next);
                Volatile.Write(ref _snapshot, next);
            }
        }

        public void Import(Stream stream)
        {
            if (stream is null)
                throw new ArgumentNullException(nameof(stream));

            if (stream.CanSeek && (stream.Length - stream.Position > MaxSerializedStateSize))
                throw new InvalidDataException($"DNS Cookie secret state exceeds the maximum size of {MaxSerializedStateSize} bytes.");

            using MemoryStream buffer = new MemoryStream(MaxSerializedStateSize);
            byte[] readBuffer = new byte[Math.Min(4096, MaxSerializedStateSize + 1)];
            int totalBytesRead = 0;

            while (true)
            {
                int bytesRead = stream.Read(readBuffer, 0, Math.Min(readBuffer.Length, MaxSerializedStateSize - totalBytesRead + 1));
                if (bytesRead == 0)
                    break;

                totalBytesRead += bytesRead;
                if (totalBytesRead > MaxSerializedStateSize)
                    throw new InvalidDataException($"DNS Cookie secret state exceeds the maximum size of {MaxSerializedStateSize} bytes.");

                buffer.Write(readBuffer, 0, bytesRead);
            }

            lock (_lock)
            {
                string tmpPath = _secretFilePath + ".tmp";
                try
                {
                    WriteSecretFile(tmpPath, buffer.ToArray());
                    Snapshot imported = LoadFileLocked(tmpPath);
                    if (imported is null)
                        throw new InvalidDataException("Imported DNS Cookie secret state is missing.");

                    if (File.Exists(_secretFilePath))
                        File.Replace(tmpPath, _secretFilePath, destinationBackupFileName: null);
                    else
                        File.Move(tmpPath, _secretFilePath);

                    RestrictSecretFilePermissions(_secretFilePath);
                    Volatile.Write(ref _snapshot, imported);
                }
                finally
                {
                    File.Delete(tmpPath);
                }
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
            internal readonly int FormatVersion;
            internal readonly byte[] Active;
            internal readonly DateTime ActiveCreatedUtc;
            internal readonly byte[] Previous;
            internal readonly DateTime? PreviousRetireUtc;
            internal readonly byte[] StagedNext;

            internal Snapshot(int formatVersion, byte[] active, DateTime activeCreatedUtc,
                byte[] previous, DateTime? previousRetireUtc, byte[] stagedNext)
            {
                if ((previous is null) != (previousRetireUtc is null))
                    throw new ArgumentException("Previous secret and retirement deadline must be specified together.");

                FormatVersion = formatVersion;
                Active = active;
                ActiveCreatedUtc = activeCreatedUtc;
                Previous = previous;
                PreviousRetireUtc = previousRetireUtc;
                StagedNext = stagedNext;
            }
        }
    }
}
