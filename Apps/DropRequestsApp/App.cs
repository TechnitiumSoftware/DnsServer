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

using DnsServerCore.ApplicationCommon;
using System;
using System.IO;
using System.Net;
using System.Text.Json;
using System.Threading.Tasks;
using TechnitiumLibrary;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DropRequests
{
    public sealed class App : IDnsApplication, IDnsRequestController
    {
        #region variables

        readonly static JsonDocumentOptions _jsonParseOptions = new JsonDocumentOptions() { CommentHandling = JsonCommentHandling.Skip };

        bool _enableBlocking;
        bool _dropMalformedRequests;
        NetworkAddress[] _allowedNetworks;
        NetworkAddress[] _blockedNetworks;
        EndPoint[] _allowedLocalEndPoints;
        BlockedQuestion[] _blockedQuestions;

        #endregion

        #region IDisposable

        public void Dispose()
        {
            //do nothing
        }

        #endregion

        #region public

        public async Task InitializeAsync(IDnsServer dnsServer, string config)
        {
            using JsonDocument jsonDocument = JsonDocument.Parse(config, _jsonParseOptions);
            JsonElement jsonConfig = jsonDocument.RootElement;

            _enableBlocking = jsonConfig.GetProperty("enableBlocking").GetBoolean();

            if (jsonConfig.TryGetProperty("dropMalformedRequests", out JsonElement jsonDropMalformedRequests))
                _dropMalformedRequests = jsonDropMalformedRequests.GetBoolean();
            else
                _dropMalformedRequests = false;

            if (jsonConfig.TryReadArray("allowedNetworks", NetworkAddress.Parse, out NetworkAddress[] allowedNetworks))
                _allowedNetworks = allowedNetworks;
            else
                _allowedNetworks = [];

            if (jsonConfig.TryReadArray("blockedNetworks", NetworkAddress.Parse, out NetworkAddress[] blockedNetworks))
                _blockedNetworks = blockedNetworks;
            else
                _blockedNetworks = [];

            if (jsonConfig.TryReadArray("allowedLocalEndPoints", EndPointExtensions.Parse, out EndPoint[] allowedLocalEndPoints))
                _allowedLocalEndPoints = allowedLocalEndPoints;
            else
                _allowedLocalEndPoints = [];

            if (jsonConfig.TryReadArray("blockedQuestions", delegate (JsonElement blockedQuestion) { return new BlockedQuestion(blockedQuestion); }, out BlockedQuestion[] blockedQuestions))
                _blockedQuestions = blockedQuestions;
            else
                _blockedQuestions = [];

            if (!jsonConfig.TryGetProperty("dropMalformedRequests", out _))
            {
                config = config.Replace("\"allowedNetworks\"", "\"dropMalformedRequests\": false,\r\n  \"allowedNetworks\"");

                await File.WriteAllTextAsync(Path.Combine(dnsServer.ApplicationFolder, "dnsApp.config"), config);
            }

            if (!jsonConfig.TryGetProperty("allowedLocalEndPoints", out _))
            {
                config = config.Replace("\"blockedQuestions\"", "\"allowedLocalEndPoints\": [\r\n    //when configured, will allow only requests coming via listed DNS server local end points and drop from any other DNS server local end point.\r\n    //intended to be used with services like DoT/DoH/DoQ\r\n  ],\r\n  \"blockedQuestions\"");

                await File.WriteAllTextAsync(Path.Combine(dnsServer.ApplicationFolder, "dnsApp.config"), config);
            }
        }

        public Task<DnsRequestControllerAction> GetRequestActionAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol)
        {
            if (!_enableBlocking)
                return Task.FromResult(DnsRequestControllerAction.Allow);

            if (_dropMalformedRequests)
            {
                if (request.ParsingException is not null)
                    return Task.FromResult(DnsRequestControllerAction.DropSilently);

                if (request.Question.Count != 1)
                    return Task.FromResult(DnsRequestControllerAction.DropSilently);
            }

            IPAddress remoteIp = remoteEP.Address;

            foreach (NetworkAddress allowedNetwork in _allowedNetworks)
            {
                if (allowedNetwork.Contains(remoteIp))
                    return Task.FromResult(DnsRequestControllerAction.Allow);
            }

            foreach (NetworkAddress blockedNetwork in _blockedNetworks)
            {
                if (blockedNetwork.Contains(remoteIp))
                    return Task.FromResult(DnsRequestControllerAction.DropSilently);
            }

            if (_allowedLocalEndPoints.Length > 0)
            {
                if ((request.Metadata is not null) && (request.Metadata.NameServer is not null))
                {
                    Uri requestLocalUriEP = request.Metadata.NameServer.DoHEndPoint;
                    if (requestLocalUriEP is not null)
                    {
                        foreach (EndPoint localEP in _allowedLocalEndPoints)
                        {
                            if (localEP is DomainEndPoint ep)
                            {
                                if (((ep.Port == 0) || (ep.Port == requestLocalUriEP.Port)) && ep.Address.Equals(requestLocalUriEP.Host, StringComparison.OrdinalIgnoreCase))
                                    return Task.FromResult(DnsRequestControllerAction.Allow);
                            }
                        }
                    }

                    DomainEndPoint requestLocalDomainEP = request.Metadata.NameServer.DomainEndPoint;
                    if (requestLocalDomainEP is not null)
                    {
                        foreach (EndPoint localEP in _allowedLocalEndPoints)
                        {
                            if (localEP is DomainEndPoint ep)
                            {
                                if (((ep.Port == 0) || (ep.Port == requestLocalDomainEP.Port)) && ep.Address.Equals(requestLocalDomainEP.Address, StringComparison.OrdinalIgnoreCase))
                                    return Task.FromResult(DnsRequestControllerAction.Allow);
                            }
                        }
                    }

                    IPEndPoint requestLocalEP = request.Metadata.NameServer.IPEndPoint;
                    if (requestLocalEP is not null)
                    {
                        foreach (EndPoint localEP in _allowedLocalEndPoints)
                        {
                            if (localEP is IPEndPoint ep)
                            {
                                if (((ep.Port == 0) || (ep.Port == requestLocalEP.Port)) && ep.Address.Equals(requestLocalEP.Address))
                                    return Task.FromResult(DnsRequestControllerAction.Allow);
                            }
                        }
                    }
                }

                return Task.FromResult(DnsRequestControllerAction.DropSilently);
            }

            DnsQuestionRecord requestQuestion = request.Question[0];

            foreach (BlockedQuestion blockedQuestion in _blockedQuestions)
            {
                if (blockedQuestion.Matches(requestQuestion))
                    return Task.FromResult(DnsRequestControllerAction.DropSilently);
            }

            return Task.FromResult(DnsRequestControllerAction.Allow);
        }

        #endregion

        #region properties

        public string Description
        { get { return "Drops incoming DNS requests that match list of blocked networks or blocked questions."; } }

        #endregion

        class BlockedQuestion
        {
            #region variables

            readonly string _name;
            readonly bool _blockZone;
            readonly DnsResourceRecordType _type;

            #endregion

            #region constructor

            public BlockedQuestion(JsonElement jsonQuestion)
            {
                if (jsonQuestion.TryGetProperty("name", out JsonElement jsonName))
                    _name = jsonName.GetString().TrimEnd('.');

                if (jsonQuestion.TryGetProperty("blockZone", out JsonElement jsonBlockZone))
                    _blockZone = jsonBlockZone.GetBoolean();

                if (jsonQuestion.TryGetProperty("type", out JsonElement jsonType))
                {
                    if (!Enum.TryParse(jsonType.GetString(), true, out DnsResourceRecordType type))
                        throw new NotSupportedException("DNS record type is not supported: " + jsonType.GetString());

                    _type = type;
                }
                else
                {
                    _type = DnsResourceRecordType.Unknown;
                }
            }

            #endregion

            #region public

            public bool Matches(DnsQuestionRecord question)
            {
                if (_name is not null)
                {
                    if (_blockZone)
                    {
                        if ((_name.Length > 0) && !_name.Equals(question.Name, StringComparison.OrdinalIgnoreCase) && !question.Name.EndsWith("." + _name, StringComparison.OrdinalIgnoreCase))
                            return false;
                    }
                    else
                    {
                        if (!_name.Equals(question.Name, StringComparison.OrdinalIgnoreCase))
                            return false;
                    }
                }

                if ((_type != DnsResourceRecordType.Unknown) && (_type != question.Type))
                    return false;

                return true;
            }

            #endregion
        }
    }
}
