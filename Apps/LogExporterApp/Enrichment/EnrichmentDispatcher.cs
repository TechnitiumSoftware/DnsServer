/*
Technitium DNS Server
Copyright (C) 2025  Shreyas Zare
Copyright (C) 2025  Zafer Balkan

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
using System.Collections.Concurrent;

namespace LogExporter.Enrichment
{
    /// <summary>
    /// Dispatches enrichment to all configured IEnrichment strategies.
    ///
    /// ADR: Enrichment is synchronous and in-process, so this dispatcher
    /// executes strategies sequentially to keep ordering deterministic.
    /// Each enricher is isolated with its own exception boundary so that
    /// one faulty enricher cannot break the pipeline.
    /// </summary>
    public sealed class EnrichmentDispatcher : IDisposable
    {
        #region variables

        private readonly ConcurrentDictionary<Type, IEnrichment> _enrichers =
            new ConcurrentDictionary<Type, IEnrichment>();

        private bool _disposed;

        #endregion

        #region IDisposable

        public void Dispose()
        {
            if (_disposed)
                return;

            _disposed = true;

            foreach (IEnrichment enricher in _enrichers.Values)
            {
                try
                {
                    enricher.Dispose();
                }
                catch
                {
                    // At this point we cannot rely on any logging infrastructure.
                    // Best-effort only: swallow to avoid secondary failures.
                }
            }

            _enrichers.Clear();
        }

        #endregion

        #region public

        public void Add(IEnrichment enricher)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (enricher == null)
                throw new ArgumentNullException(nameof(enricher));

            _enrichers.AddOrUpdate(
                enricher.GetType(),
                enricher,
                (_, existing) =>
                {
                    // Replace existing instance defensively.
                    try
                    {
                        existing.Dispose();
                    }
                    catch
                    {
                        // Ignore disposal failure; new instance still becomes active.
                    }

                    return enricher;
                });
        }

        public void Remove(Type type)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            ArgumentNullException.ThrowIfNull(type);

            if (_enrichers.TryRemove(type, out IEnrichment? existing))
            {
                try
                {
                    existing.Dispose();
                }
                catch
                {
                    // Isolation: disposal of one enricher must not affect others.
                }
            }
        }

        public bool Any()
        {
            if (_disposed)
                return false;

            return !_enrichers.IsEmpty;
        }

        /// <summary>
        /// Runs all configured enrichment strategies on a single log entry.
        /// Errors are reported to the optional error callback but never thrown.
        /// </summary>
        public void Enrich(LogEntry logEntry, Action<Exception>? onError = null)
        {
            if (_disposed || logEntry == null || _enrichers.IsEmpty)
                return;

            foreach (IEnrichment enricher in _enrichers.Values)
            {
                try
                {
                    enricher.Enrich(logEntry);
                }
                catch (Exception ex)
                {
                    onError?.Invoke(ex);
                }
            }
        }

        #endregion
    }
}
