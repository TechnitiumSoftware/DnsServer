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
    public enum DnsCookieSecretRolloverState : byte
    {
        None,
        Staged,
        Activated
    }

    public class DnsCookieSecretManager
    {
        #region constants

        private const int LegacyFileVersion = 1;
        private const int PreviousFileVersion = 2;
        // Version 3 was emitted with rollover state before the timestamp. Retain a
        // dedicated reader for that layout so existing instances can migrate safely.
        private const int BrokenCurrentFileVersion = 3;
        private const int PreviousCurrentFileVersion = 4;
        private const int CurrentFileVersion = 5;

        // RFC 9018 Version 1 uses SipHash-2-4, which has a 128-bit key. New state
        // is always exactly this size; a larger persisted legacy secret is read using
        // its historical first-16-byte effective key and normalized on the next write.
        internal const int EffectiveSecretLength = 16;
        private const int LegacySecretMaxLength = 256;

        // Serialized state contains versioned timestamps and length fields for the
        // active, previous-validation, and manually staged secrets. The read limit
        // permits legacy storage until it is legitimately rewritten.
        private const int SerializedMetadataSize = sizeof(int) + (2 * sizeof(long)) + (3 * sizeof(int));
        internal const int MaxSerializedStateSize = SerializedMetadataSize + (3 * LegacySecretMaxLength);

        private const int DefaultSecretLen = EffectiveSecretLength;

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
                    loaded = new Snapshot(CurrentFileVersion, 0, DnsCookieSecretRolloverState.None,
                        GenerateSecret(), DateTime.UtcNow, null);
                    SaveLocked(loaded);
                }
                // Legacy storage remains untouched at startup. It is read through the
                // first-16-byte effective key and becomes canonical only when a later
                // lifecycle operation legitimately persists a replacement snapshot.

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

                if (version == BrokenCurrentFileVersion)
                    return ReadBrokenVersion3(br, stream, version);

                long generation = version == CurrentFileVersion ? br.ReadInt64() : 0;
                if (generation < 0)
                    throw new InvalidDataException("Invalid DNS Cookie secret generation.");

                DateTime createdUtc = ReadCreatedUtc(br);
                byte[] active = ReadActiveSecret(br);

                if (version == CurrentFileVersion || version == PreviousCurrentFileVersion)
                {
                    DnsCookieSecretRolloverState rolloverState = ReadRolloverState(br);
                    byte[] secondary = ReadOptionalSecret(br, "secondary");
                    EnsureEndOfFile(stream);
                    return new Snapshot(version, generation, rolloverState, active, createdUtc, secondary);
                }

                byte[] legacySecondary;
                if (version == LegacyFileVersion)
                {
                    legacySecondary = ReadOptionalSecret(br, "staging");
                }
                else if (version == PreviousFileVersion)
                {
                    // Version 2 could store an ambiguous previous and staged slot. Its
                    // format cannot prove intent, so retain one existing secondary as
                    // validation-only rather than ever auto-activating it.
                    _ = br.ReadInt64(); // legacy retirement metadata
                    byte[] previous = ReadOptionalSecret(br, "previous");
                    byte[] stagedNext = ReadOptionalSecret(br, "staged next");
                    legacySecondary = previous ?? stagedNext;
                }
                else
                {
                    throw new InvalidDataException($"Unsupported DNS Cookie secret state version: {version}.");
                }

                EnsureEndOfFile(stream);
                return new Snapshot(version, 0,
                    legacySecondary is null ? DnsCookieSecretRolloverState.None : DnsCookieSecretRolloverState.Activated,
                    active, createdUtc, legacySecondary);
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

        private static DateTime ReadCreatedUtc(BinaryReader reader)
        {
            long createdUtcTicks = reader.ReadInt64();
            if (createdUtcTicks < DateTime.MinValue.Ticks || createdUtcTicks > DateTime.MaxValue.Ticks)
                throw new InvalidDataException("Invalid DNS Cookie secret creation timestamp.");

            return new DateTime(createdUtcTicks, DateTimeKind.Utc);
        }

        private static byte[] ReadActiveSecret(BinaryReader reader)
        {
            int currentLen = reader.ReadInt32();
            if (currentLen < EffectiveSecretLength || currentLen > LegacySecretMaxLength)
                throw new InvalidDataException("Invalid current secret length.");

            byte[] active = reader.ReadBytes(currentLen);
            if (active.Length != currentLen)
                throw new EndOfStreamException("Unexpected end of secret file (active secret).");

            return ToEffectiveSecret(active);
        }

        private static byte[] ReadOptionalSecret(BinaryReader reader, string name)
        {
            int length = reader.ReadInt32();
            if (length == 0)
                return null;
            if (length < EffectiveSecretLength || length > LegacySecretMaxLength)
                throw new InvalidDataException($"Invalid {name} secret length.");
            byte[] value = reader.ReadBytes(length);
            if (value.Length != length)
                throw new EndOfStreamException($"Unexpected end of secret file ({name} secret).");
            return ToEffectiveSecret(value);
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
            activeId = SecretId(snapshot.Active);
            stagingId = SecretId(GetSecondary(snapshot, DnsCookieSecretRolloverState.Staged));
            activeCreatedUtc = snapshot.ActiveCreatedUtc;
        }

        // Version 3 wrote the same fields in a different order, so it needs its own reader
        // even though the individual field readers are shared with the current layout.
        private static Snapshot ReadBrokenVersion3(BinaryReader br, Stream stream, int version)
        {
            DnsCookieSecretRolloverState rolloverState = ReadRolloverState(br);
            DateTime createdUtc = ReadCreatedUtc(br);
            byte[] active = ReadActiveSecret(br);
            byte[] secondary = ReadOptionalSecret(br, "secondary");
            EnsureEndOfFile(stream);
            return new Snapshot(version, 0, rolloverState, active, createdUtc, secondary);
        }

        private static DnsCookieSecretRolloverState ReadRolloverState(BinaryReader br)
        {
            DnsCookieSecretRolloverState rolloverState = (DnsCookieSecretRolloverState)br.ReadByte();
            if (!Enum.IsDefined(rolloverState))
                throw new InvalidDataException("Invalid DNS Cookie secret rollover state.");
            return rolloverState;
        }

        private void SaveLocked(Snapshot snapshot)
        {
            // Caller must hold _lock
            ArgumentNullException.ThrowIfNull(snapshot);

            if (snapshot.Active is null || snapshot.Active.Length != EffectiveSecretLength)
                throw new InvalidOperationException("Active secret is missing or has an invalid length.");

            byte[] contents;
            using (MemoryStream ms = new MemoryStream())
            {
                using (BinaryWriter bw = new BinaryWriter(ms))
                {
                    bw.Write(CurrentFileVersion);
                    bw.Write(snapshot.Generation);
                    bw.Write(snapshot.ActiveCreatedUtc.Ticks);

                    bw.Write(snapshot.Active.Length);
                    bw.Write(snapshot.Active);
                    bw.Write((byte)snapshot.RolloverState);
                    WriteOptionalSecret(bw, snapshot.Secondary, "secondary");
                }

                contents = ms.ToArray();
            }

            if (contents.Length > MaxSerializedStateSize)
                throw new InvalidOperationException("DNS Cookie secret state exceeds its maximum serialized size.");

            string directory = Path.GetDirectoryName(_secretFilePath);
            if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
                Directory.CreateDirectory(directory);

            string tmpPath = _secretFilePath + ".tmp";
            WriteSecretFile(tmpPath, contents);
            CommitSecretFile(tmpPath);
        }

        /// <summary>Atomically replaces the live state file with a fully written temporary file.</summary>
        private void CommitSecretFile(string tmpPath)
        {
            // Atomic replace where supported
            if (File.Exists(_secretFilePath))
                File.Replace(tmpPath, _secretFilePath, destinationBackupFileName: null);
            else
                File.Move(tmpPath, _secretFilePath);

            RestrictSecretFilePermissions(_secretFilePath);
        }

        /// <summary>
        /// Runs one secret lifecycle change under the lock: check the caller's expected
        /// generation, build the replacement snapshot, persist it, then publish it. A
        /// <see langword="null"/> result from <paramref name="transform"/> means the state
        /// declined to move and nothing is written.
        /// </summary>
        private bool Transition(long? expectedGeneration, Func<Snapshot, Snapshot> transform)
        {
            lock (_lock)
            {
                Snapshot current = Volatile.Read(ref _snapshot);
                EnsureExpectedGeneration(current, expectedGeneration);

                Snapshot next = transform(current);
                if (next is null)
                    return false;

                SaveLocked(next);
                Volatile.Write(ref _snapshot, next);
                return true;
            }
        }

        private static void WriteOptionalSecret(BinaryWriter writer, byte[] secret, string name)
        {
            if (secret is null)
            {
                writer.Write(0);
                return;
            }
            if (secret.Length != EffectiveSecretLength)
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

        private static byte[] ToEffectiveSecret(ReadOnlySpan<byte> secret)
        {
            if (secret.Length < EffectiveSecretLength)
                throw new ArgumentException($"Secret must contain at least {EffectiveSecretLength} bytes.", nameof(secret));

            return secret[..EffectiveSecretLength].ToArray();
        }

        /// <summary>The secondary slot only holds a secret while the rollover is in the matching state.</summary>
        private static byte[] GetSecondary(Snapshot snapshot, DnsCookieSecretRolloverState requiredState)
        {
            return snapshot.RolloverState == requiredState ? snapshot.Secondary : null;
        }

        private static byte[] CopySecret(byte[] secret) => secret is null ? null : (byte[])secret.Clone();

        private static string SecretId(byte[] secret) => secret is null ? null : Convert.ToHexString(SHA256.HashData(secret));

        #endregion

        #region public

        // A standalone automatic rotation can safely stage and activate a new secret, but it
        // cannot determine the longest TTL served by every configured zone. RFC 9018 §5
        // recommends retaining the previous secret for at least that TTL plus one hour, so
        // automatic rotation deliberately stops after activation and leaves retirement to an
        // explicit, TTL-aware operator action.
        public bool Rotate()
        {
            return Transition(null, current => current.RolloverState switch
            {
                DnsCookieSecretRolloverState.None => new Snapshot(CurrentFileVersion, NextGeneration(current),
                    DnsCookieSecretRolloverState.Staged, current.Active, current.ActiveCreatedUtc, GenerateSecret()),
                DnsCookieSecretRolloverState.Staged => new Snapshot(CurrentFileVersion, NextGeneration(current),
                    DnsCookieSecretRolloverState.Activated, current.Secondary, DateTime.UtcNow, current.Active),
                DnsCookieSecretRolloverState.Activated => null, //retirement stays manual
                _ => throw new InvalidOperationException("The DNS Cookie rollover state is invalid.")
            });
        }

        // Management-facing copies prevent callers from mutating published secret material.
        public byte[] Active => CopySecret(Volatile.Read(ref _snapshot)?.Active);

        public byte[] Staging => CopySecret(GetSecondary(Volatile.Read(ref _snapshot), DnsCookieSecretRolloverState.Staged));

        public byte[] Previous => CopySecret(GetSecondary(Volatile.Read(ref _snapshot), DnsCookieSecretRolloverState.Activated));

        public DnsCookieSecretRolloverState RolloverState => Volatile.Read(ref _snapshot).RolloverState;

        public long Generation => Volatile.Read(ref _snapshot).Generation;

        public DateTime ActiveCreatedUtc => Volatile.Read(ref _snapshot).ActiveCreatedUtc;

        public string ActiveId => SecretId(Volatile.Read(ref _snapshot).Active);

        public string StagingId => SecretId(GetSecondary(Volatile.Read(ref _snapshot), DnsCookieSecretRolloverState.Staged));

        internal void GetStatus(out string activeId, out string stagingId, out DateTime activeCreatedUtc)
        {
            GetStatus(Volatile.Read(ref _snapshot), out activeId, out stagingId, out activeCreatedUtc);
        }

        internal DateTime GetNextTransitionUtc(TimeSpan rotationPeriod)
        {
            if (rotationPeriod <= TimeSpan.Zero)
                throw new ArgumentOutOfRangeException(nameof(rotationPeriod));

            Snapshot snapshot = Volatile.Read(ref _snapshot);
            return snapshot.RolloverState switch
            {
                DnsCookieSecretRolloverState.None => snapshot.ActiveCreatedUtc + rotationPeriod,
                DnsCookieSecretRolloverState.Staged => DateTime.UtcNow,
                DnsCookieSecretRolloverState.Activated => DateTime.MaxValue,
                _ => throw new InvalidOperationException("The DNS Cookie rollover state is invalid.")
            };
        }

        internal void GetSecrets(out byte[] active, out byte[] staging, out byte[] previous)
        {
            Snapshot snapshot = Volatile.Read(ref _snapshot);
            active = CopySecret(snapshot.Active);
            staging = CopySecret(GetSecondary(snapshot, DnsCookieSecretRolloverState.Staged));
            previous = CopySecret(GetSecondary(snapshot, DnsCookieSecretRolloverState.Activated));
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
        public void AddStaging() => GenerateStagedSecret();

        public void GenerateStagedSecret(long? expectedGeneration = null) => StageSecret(GenerateSecret(), expectedGeneration);

        public void StageSecret(ReadOnlySpan<byte> secret, long? expectedGeneration = null)
        {
            if (secret.Length != EffectiveSecretLength)
                throw new ArgumentException($"Secret must be exactly {EffectiveSecretLength} bytes.", nameof(secret));

            // Copy before publication so a caller cannot mutate the staged key after this
            // operation returns, even when the source span wraps a mutable byte array.
            byte[] stagedSecret = secret.ToArray();

            Transition(expectedGeneration, current =>
            {
                if (current.RolloverState != DnsCookieSecretRolloverState.None)
                    throw new InvalidOperationException("A DNS Cookie rollover is already in progress.");

                return new Snapshot(CurrentFileVersion, NextGeneration(current), DnsCookieSecretRolloverState.Staged,
                    current.Active, current.ActiveCreatedUtc, stagedSecret);
            });
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
        public void ActivateStaging(long? expectedGeneration = null)
        {
            Transition(expectedGeneration, current =>
            {
                if (current.RolloverState != DnsCookieSecretRolloverState.Staged || current.Secondary is null)
                    throw new InvalidOperationException("There is no staging secret to activate.");

                return new Snapshot(CurrentFileVersion, NextGeneration(current), DnsCookieSecretRolloverState.Activated,
                    current.Secondary, DateTime.UtcNow, current.Active);
            });
        }

        /// <summary>
        /// Drops the staged secret without activating it. Call this to abort a staged transition.
        ///
        /// This is used when a staged secret transition is no longer needed (e.g., if key rotation
        /// was postponed or cancelled). Operators should consult RFC 9018 §5 and APIDOCS.md
        /// DNS Cookie section when making manual secret management decisions.
        /// </summary>
        public void DropStaging(long? expectedGeneration = null)
        {
            Transition(expectedGeneration, current =>
            {
                if (current.RolloverState != DnsCookieSecretRolloverState.Staged)
                    throw new InvalidOperationException("There is no staging secret to drop.");

                return new Snapshot(CurrentFileVersion, NextGeneration(current), DnsCookieSecretRolloverState.None,
                    current.Active, current.ActiveCreatedUtc, null);
            });
        }

        public void RetirePrevious(long? expectedGeneration = null)
        {
            Transition(expectedGeneration, current =>
            {
                if (current.RolloverState != DnsCookieSecretRolloverState.Activated)
                    throw new InvalidOperationException("There is no previous DNS Cookie secret to retire.");

                return new Snapshot(CurrentFileVersion, NextGeneration(current), DnsCookieSecretRolloverState.None,
                    current.Active, current.ActiveCreatedUtc, null);
            });
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

                    Snapshot current = Volatile.Read(ref _snapshot);
                    if (imported.Generation < current.Generation)
                        throw new InvalidDataException("Imported DNS Cookie secret state is older than the currently published generation.");

                    CommitSecretFile(tmpPath);
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

        private static void EnsureExpectedGeneration(Snapshot snapshot, long? expectedGeneration)
        {
            if (expectedGeneration.HasValue && expectedGeneration.Value != snapshot.Generation)
                throw new InvalidOperationException($"DNS Cookie secret generation changed from {expectedGeneration.Value} to {snapshot.Generation}; refresh state before retrying.");
        }

        private static long NextGeneration(Snapshot snapshot)
        {
            if (snapshot.Generation == long.MaxValue)
                throw new InvalidOperationException("DNS Cookie secret generation has reached its maximum value.");
            return snapshot.Generation + 1;
        }

        private sealed class Snapshot
        {
            internal readonly int FormatVersion;
            internal readonly long Generation;
            internal readonly DnsCookieSecretRolloverState RolloverState;
            internal readonly byte[] Active;
            internal readonly DateTime ActiveCreatedUtc;
            internal readonly byte[] Secondary;

            internal Snapshot(int formatVersion, long generation, DnsCookieSecretRolloverState rolloverState,
                byte[] active, DateTime activeCreatedUtc, byte[] secondary)
            {
                if (generation < 0)
                    throw new ArgumentOutOfRangeException(nameof(generation));
                if (!Enum.IsDefined(rolloverState))
                    throw new ArgumentOutOfRangeException(nameof(rolloverState));
                if (active is null)
                    throw new ArgumentNullException(nameof(active));
                if ((rolloverState == DnsCookieSecretRolloverState.None) != (secondary is null))
                    throw new ArgumentException("A secondary secret is required only while a rollover is in progress.", nameof(secondary));

                FormatVersion = formatVersion;
                Generation = generation;
                RolloverState = rolloverState;
                Active = ToEffectiveSecret(active);
                ActiveCreatedUtc = activeCreatedUtc;
                Secondary = secondary is null ? null : ToEffectiveSecret(secondary);
            }
        }
    }
}
