/*
Technitium DNS Server
Copyright (C) 2026  Shreyas Zare (shreyas@technitium.com)

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

namespace DnsServerCore.ApplicationCommon
{
    /// <summary>
    /// Optionally provides an app-owned HTML editor for an APP record handler.
    /// </summary>
    public interface IDnsAppRecordEditor
    {
        /// <summary>
        /// A self-contained HTML document with inline styles and scripts, or null to use
        /// the raw record data editor. The console hosts this document in a sandboxed iframe.
        /// See Apps/RECORD-EDITORS.md for the message protocol and security restrictions.
        /// </summary>
        string? ApplicationRecordDataEditor { get; }
    }
}
