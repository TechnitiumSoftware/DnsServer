/*
Technitium DNS Server
Copyright (C) 2025  Shreyas Zare (shreyas@technitium.com)
Copyright (C) 2025  Zafer Balkan (zafer@zaferbalkan.com)

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
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace LogExporter.Strategy
{
    public sealed class ExportManager : IDisposable
    {
        #region variables

        readonly ConcurrentDictionary<Type, IExportStrategy> _exportStrategies = new ConcurrentDictionary<Type, IExportStrategy>();

        #endregion

        #region IDisposable

        public void Dispose()
        {
            foreach (KeyValuePair<Type, IExportStrategy> exportStrategy in _exportStrategies)
                exportStrategy.Value.Dispose();
        }

        #endregion

        #region public

        public void AddStrategy(IExportStrategy strategy)
        {
            if (!_exportStrategies.TryAdd(strategy.GetType(), strategy))
                throw new InvalidOperationException();
        }

        public void RemoveStrategy(Type type)
        {
            if (_exportStrategies.TryRemove(type, out IExportStrategy? existing))
                existing?.Dispose();
        }

        public bool HasStrategy()
        {
            return !_exportStrategies.IsEmpty;
        }

        /// <summary>
        /// Executes all configured export strategies for the current batch.
        ///
        /// ADR: we deliberately await the ExportAsync tasks directly instead of using
        /// Task.Factory.StartNew with async delegates. The previous implementation
        /// created Task&lt;Task&gt; wrappers and only awaited the outer tasks, which meant
        /// exports could continue running after this method returned and exceptions
        /// were surfaced as unobserved task exceptions. Keeping a simple
        /// Task.WhenAll over the real strategy tasks guarantees:
        ///   - backpressure semantics: a slow exporter slows the pipeline predictably
        ///   - correct exception propagation to the background worker
        ///   - no fire-and-forget work that can outlive shutdown
        /// Do not reintroduce Task.Run/StartNew here unless you also handle the
        /// Task&lt;Task&gt; layering explicitly.
        /// </summary>
        public async Task ImplementStrategyAsync(IReadOnlyList<LogEntry> logs, CancellationToken token = default)
        {
            if (logs == null || logs.Count == 0 || _exportStrategies.IsEmpty)
                return;

            var tasks = new List<Task>(_exportStrategies.Count);

            foreach (var strategy in _exportStrategies.Values)
            {
                tasks.Add(strategy.ExportAsync(logs, token));
            }

            await Task.WhenAll(tasks).ConfigureAwait(false);
        }

        #endregion
    }
}
