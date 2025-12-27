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

namespace LogExporter.Pipeline
{
    /// <summary>
    /// Dispatches pipeline actions to all configured IPipelineProcessor strategies.
    ///
    /// ADR: Meta is synchronous and in-process, so this dispatcher
    /// executes strategies sequentially to keep ordering deterministic.
    /// Each processor is isolated with its own exception boundary so that
    /// one faulty processor cannot break the pipeline.
    /// </summary>
    public sealed class PipelineDispatcher : IDisposable
    {
        #region variables

        private readonly ConcurrentDictionary<Type, IPipelineProcessor> _processors =
            new ConcurrentDictionary<Type, IPipelineProcessor>();

        private bool _disposed;

        #endregion

        #region IDisposable

        public void Dispose()
        {
            if (_disposed)
                return;

            _disposed = true;

            foreach (IPipelineProcessor enricher in _processors.Values)
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

            _processors.Clear();
        }

        #endregion

        #region public

        public void Add(IPipelineProcessor processor)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            ArgumentNullException.ThrowIfNull(processor);

            _processors.AddOrUpdate(
                processor.GetType(),
                processor,
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

                    return processor;
                });
        }

        public void Remove(Type type)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            ArgumentNullException.ThrowIfNull(type);

            if (_processors.TryRemove(type, out IPipelineProcessor? existing))
            {
                try
                {
                    existing.Dispose();
                }
                catch
                {
                    // Isolation: disposal of one processor must not affect others.
                }
            }
        }

        public bool Any()
        {
            if (_disposed)
                return false;

            return !_processors.IsEmpty;
        }

        /// <summary>
        /// Runs all configured enrichment strategies on a single log entry.
        /// Errors are reported to the optional error callback but never thrown.
        /// </summary>
        public void Run(LogEntry logEntry, Action<Exception>? onError = null)
        {
            if (_disposed || logEntry == null || _processors.IsEmpty)
                return;

            foreach (IPipelineProcessor processor in _processors.Values)
            {
                try
                {
                    processor.Process(logEntry);
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
