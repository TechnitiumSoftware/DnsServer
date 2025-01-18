/*
Technitium DNS Server
Copyright (C) 2025  Shreyas Zare (shreyas@technitium.com)

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

        public async Task ImplementStrategyAsync(IReadOnlyList<LogEntry> logs)
        {
            List<Task> tasks = new List<Task>(_exportStrategies.Count);

            foreach (KeyValuePair<Type, IExportStrategy> strategy in _exportStrategies)
            {
                tasks.Add(Task.Factory.StartNew(delegate (object? state)
                {
                    return strategy.Value.ExportAsync(logs);
                }, null, CancellationToken.None, TaskCreationOptions.DenyChildAttach, TaskScheduler.Current));
            }

            await Task.WhenAll(tasks);
        }

        #endregion
    }
}
