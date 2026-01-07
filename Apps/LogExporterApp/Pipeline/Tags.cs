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
using System.Collections.Generic;
using System.Linq;

namespace LogExporter.Pipeline
{
    public partial class Tags : IPipelineProcessor
    {
        private readonly string[] _tags; 
        public Tags(IEnumerable<string> tags)
        {
            _tags = tags.ToArray();
        }

        public void Process(LogEntry logEntry)
        {
            logEntry.Meta["tags"] = _tags;
        }

        public void Dispose()
        {
            // If DomainCache ever needs disposal, do it here.
            GC.SuppressFinalize(this);
        }
    }
}