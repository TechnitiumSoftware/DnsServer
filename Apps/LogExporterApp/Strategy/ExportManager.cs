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

        private readonly ConcurrentDictionary<Type, IExportStrategy> _exportStrategies =
            new ConcurrentDictionary<Type, IExportStrategy>();

        private bool _disposed;

        #endregion

        #region IDisposable

        public void Dispose()
        {
            if (_disposed)
                return;

            _disposed = true;

            // ADR: Once the manager is disposed, all strategies must be disposed and
            // removed. Leaving them in the dictionary creates a misleading state
            // (“manager has strategies”) and allows accidental use-after-dispose.
            // Clearing ensures the manager becomes inert and conveys finality.
            foreach (KeyValuePair<Type, IExportStrategy> entry in _exportStrategies)
                entry.Value.Dispose();

            _exportStrategies.Clear();
        }

        #endregion

        #region public

        public void AddStrategy(IExportStrategy strategy)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            if (!_exportStrategies.TryAdd(strategy.GetType(), strategy))
                throw new InvalidOperationException(
                    $"Strategy of type {strategy.GetType().Name} already registered.");
        }

        public void RemoveStrategy(Type type)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            if (_exportStrategies.TryRemove(type, out IExportStrategy? existing))
                existing?.Dispose();
        }

        public bool HasStrategy()
        {
            if (_disposed)
                return false;

            return !_exportStrategies.IsEmpty;
        }

        /// <summary>
        /// Executes all configured export strategies for the current batch.
        ///
        /// ADR: ExportManager synchronously awaits each strategy's ExportAsync task.
        /// This guarantees predictable backpressure and ensures no spillover work
        /// continues after shutdown. Strategies are responsible for honoring
        /// cancellation so shutdown stays bounded.
        /// </summary>
        public async Task UseStrategyAsync(IReadOnlyList<LogEntry> logs, CancellationToken token)
        {
            if (_disposed || logs == null || logs.Count == 0 || _exportStrategies.IsEmpty)
                return;

            List<Task> tasks = new List<Task>(_exportStrategies.Count);

            foreach (IExportStrategy strategy in _exportStrategies.Values)
                tasks.Add(strategy.ExportAsync(logs, token));

            await Task.WhenAll(tasks).ConfigureAwait(false);
        }

        #endregion
    }
}
