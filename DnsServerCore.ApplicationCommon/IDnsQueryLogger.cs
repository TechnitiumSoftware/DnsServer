/*
Technitium DNS Server
Copyright (C) 2021  Shreyas Zare (shreyas@technitium.com)

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
using System.Net;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;

namespace DnsServerCore.ApplicationCommon
{
    public enum DnsServerResponseType : byte
    {
        Authoritative = 1,
        Recursive = 2,
        Cached = 3,
        Blocked = 4
    }

    /// <summary>
    /// Allows a DNS App to log incoming DNS requests and their corresponding responses.
    /// </summary>
    public interface IDnsQueryLogger
    {
        /// <summary>
        /// Allows a DNS App to log incoming DNS requests and responses. This method is called by the DNS Server after an incoming request is processed and a response is sent.
        /// </summary>
        /// <param name="timestamp">The time stamp of the log entry.</param>
        /// <param name="request">The incoming DNS request that was received.</param>
        /// <param name="remoteEP">The end point (IP address and port) of the client making the request.</param>
        /// <param name="protocol">The protocol using which the request was received.</param>
        /// <param name="response">The DNS response that was sent.</param>
        Task InsertLogAsync(DateTime timestamp, DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, DnsDatagram response);

        /// <summary>
        /// Allows DNS Server HTTP API to query the logs recorded by the DNS App.
        /// </summary>
        /// <param name="pageNumber">The page number to be displayed to the user.</param>
        /// <param name="entriesPerPage">Total entries per page.</param>
        /// <param name="descendingOrder">Lists log entries in descending order.</param>
        /// <param name="start">Optional parameter to filter records by start date time.</param>
        /// <param name="end">Optional parameter to filter records by end date time.</param>
        /// <param name="clientIpAddress">Optional parameter to filter records by the client IP address.</param>
        /// <param name="protocol">Optional parameter to filter records by the DNS transport protocol.</param>
        /// <param name="responseType">Optional parameter to filter records by the type of response.</param>
        /// <param name="rcode">Optional parameter to filter records by the response code.</param>
        /// <param name="qname">Optional parameter to filter records by the request QNAME.</param>
        /// <param name="qtype">Optional parameter to filter records by the request QTYPE.</param>
        /// <param name="qclass">Optional parameter to filter records by the request QCLASS.</param>
        /// <returns>The <code>DnsLogPage</code> object that contains all the entries in the requested page number.</returns>
        Task<DnsLogPage> QueryLogsAsync(long pageNumber, int entriesPerPage, bool descendingOrder, DateTime? start, DateTime? end, IPAddress clientIpAddress, DnsTransportProtocol? protocol, DnsServerResponseType? responseType, DnsResponseCode? rcode, string qname, DnsResourceRecordType? qtype, DnsClass? qclass);
    }

    public class DnsLogPage
    {
        #region variables

        readonly long _pageNumber;
        readonly long _totalPages;
        readonly long _totalEntries;
        readonly IReadOnlyList<DnsLogEntry> _entries;

        #endregion

        #region constructor

        /// <summary>
        /// Creates a new object initialized with all the log page parameters.
        /// </summary>
        /// <param name="pageNumber">The actual page number of the selected data set.</param>
        /// <param name="totalPages">The total pages for the selected data set.</param>
        /// <param name="totalEntries">The total number of entries in the selected data set.</param>
        /// <param name="entries">The DNS log entries in this page.</param>
        public DnsLogPage(long pageNumber, long totalPages, long totalEntries, IReadOnlyList<DnsLogEntry> entries)
        {
            _pageNumber = pageNumber;
            _totalPages = totalPages;
            _totalEntries = totalEntries;
            _entries = entries;
        }

        #endregion

        #region properties

        /// <summary>
        /// The actual page number of the selected data set.
        /// </summary>
        public long PageNumber
        { get { return _pageNumber; } }

        /// <summary>
        /// The total pages for the selected data set.
        /// </summary>
        public long TotalPages
        { get { return _totalPages; } }

        /// <summary>
        /// The total number of entries in the selected data set.
        /// </summary>
        public long TotalEntries
        { get { return _totalEntries; } }

        /// <summary>
        /// The DNS log entries in this page.
        /// </summary>
        public IReadOnlyList<DnsLogEntry> Entries
        { get { return _entries; } }

        #endregion
    }

    public class DnsLogEntry
    {
        #region variables

        readonly long _rowNumber;
        readonly DateTime _timestamp;
        readonly IPAddress _clientIpAddress;
        readonly DnsTransportProtocol _protocol;
        readonly DnsServerResponseType _responseType;
        readonly DnsResponseCode _rcode;
        readonly DnsQuestionRecord _question;
        readonly string _answer;

        #endregion

        #region constructor

        /// <summary>
        /// Creates a new object initialized with all the log entry parameters.
        /// </summary>
        /// <param name="rowNumber">The row number of the entry in the selected data set.</param>
        /// <param name="timestamp">The time stamp of the log entry.</param>
        /// <param name="clientIpAddress">The client IP address of the request.</param>
        /// <param name="protocol">The DNS transport protocol of the request.</param>
        /// <param name="responseType">The type of response sent by the DNS server.</param>
        /// <param name="rcode">The response code sent by the DNS server.</param>
        /// <param name="question">The question section in the request.</param>
        /// <param name="answer">The answer in text format sent by the DNS server.</param>
        public DnsLogEntry(long rowNumber, DateTime timestamp, IPAddress clientIpAddress, DnsTransportProtocol protocol, DnsServerResponseType responseType, DnsResponseCode rcode, DnsQuestionRecord question, string answer)
        {
            _rowNumber = rowNumber;
            _timestamp = timestamp;
            _clientIpAddress = clientIpAddress;
            _protocol = protocol;
            _responseType = responseType;
            _rcode = rcode;
            _question = question;
            _answer = answer;

            switch (_timestamp.Kind)
            {
                case DateTimeKind.Local:
                    _timestamp = _timestamp.ToUniversalTime();
                    break;

                case DateTimeKind.Unspecified:
                    _timestamp = DateTime.SpecifyKind(_timestamp, DateTimeKind.Utc);
                    break;
            }
        }

        #endregion

        #region properties

        /// <summary>
        /// The row number of the entry in the selected data set.
        /// </summary>
        public long RowNumber
        { get { return _rowNumber; } }

        /// <summary>
        /// The time stamp of the log entry.
        /// </summary>
        public DateTime Timestamp
        { get { return _timestamp; } }

        /// <summary>
        /// The client IP address of the request.
        /// </summary>
        public IPAddress ClientIpAddress
        { get { return _clientIpAddress; } }

        /// <summary>
        /// The DNS transport protocol of the request.
        /// </summary>
        public DnsTransportProtocol Protocol
        { get { return _protocol; } }

        /// <summary>
        /// The type of response sent by the DNS server.
        /// </summary>
        public DnsServerResponseType ResponseType
        { get { return _responseType; } }

        /// <summary>
        /// The response code sent by the DNS server.
        /// </summary>
        public DnsResponseCode RCODE
        { get { return _rcode; } }

        /// <summary>
        /// The question section in the request.
        /// </summary>
        public DnsQuestionRecord Question
        { get { return _question; } }

        /// <summary>
        /// The answer in text format sent by the DNS server.
        /// </summary>
        public string Answer
        { get { return _answer; } }

        #endregion
    }
}
