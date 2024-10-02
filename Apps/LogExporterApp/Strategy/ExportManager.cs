/*
Technitium DNS Server
Copyright (C) 2024  Shreyas Zare (shreyas@technitium.com)

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
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace LogExporter.Strategy
{
    public class ExportManager
    {
        #region variables

        private readonly Dictionary<Type, IExportStrategy> _exportStrategies;

        #endregion variables

        #region constructor

        public ExportManager()
        {
            _exportStrategies = new Dictionary<Type, IExportStrategy>();
        }

        #endregion constructor

        #region public

        public IExportStrategy? GetStrategy<T>() where T : IExportStrategy
        {
            _exportStrategies.TryGetValue(typeof(T), out var strategy);
            return strategy;
        }

        public async Task ImplementStrategyForAsync(List<LogEntry> logs, CancellationToken cancellationToken = default)
        {
            foreach (var strategy in _exportStrategies.Values)
            {
                await strategy.ExportLogsAsync(logs, cancellationToken);
            }
        }

        public void AddOrReplaceStrategy(IExportStrategy strategy)
        {
            _exportStrategies[strategy.GetType()] = strategy;
        }

        #endregion public
    }
}