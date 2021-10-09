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

using DnsServerCore.ApplicationCommon;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Threading.Tasks;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;

namespace DropRequests
{
    public class App : IDnsApplication, IDnsRequestController
    {
        #region variables

        bool _enableBlocking;
        bool _dropMalformedRequests;
        IReadOnlyList<NetworkAddress> _allowedNetworks;
        IReadOnlyList<NetworkAddress> _blockedNetworks;
        IReadOnlyList<BlockedQuestion> _blockedQuestions;

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
            dynamic jsonConfig = JsonConvert.DeserializeObject(config);

            _enableBlocking = jsonConfig.enableBlocking.Value;

            if (jsonConfig.dropMalformedRequests is null)
                _dropMalformedRequests = false;
            else
                _dropMalformedRequests = jsonConfig.dropMalformedRequests.Value;

            if (jsonConfig.allowedNetworks is null)
            {
                _allowedNetworks = Array.Empty<NetworkAddress>();
            }
            else
            {
                List<NetworkAddress> allowedNetworks = new List<NetworkAddress>();

                foreach (dynamic allowedNetwork in jsonConfig.allowedNetworks)
                {
                    allowedNetworks.Add(NetworkAddress.Parse(allowedNetwork.Value));
                }

                _allowedNetworks = allowedNetworks;
            }

            if (jsonConfig.blockedNetworks is null)
            {
                _blockedNetworks = Array.Empty<NetworkAddress>();
            }
            else
            {
                List<NetworkAddress> blockedNetworks = new List<NetworkAddress>();

                foreach (dynamic blockedNetwork in jsonConfig.blockedNetworks)
                {
                    blockedNetworks.Add(NetworkAddress.Parse(blockedNetwork.Value));
                }

                _blockedNetworks = blockedNetworks;
            }

            if (jsonConfig.blockedQuestions is null)
            {
                _blockedQuestions = Array.Empty<BlockedQuestion>();
            }
            else
            {
                List<BlockedQuestion> blockedQuestions = new List<BlockedQuestion>();

                foreach (dynamic blockedQuestion in jsonConfig.blockedQuestions)
                {
                    blockedQuestions.Add(new BlockedQuestion(blockedQuestion));
                }

                _blockedQuestions = blockedQuestions;
            }

            if (jsonConfig.dropMalformedRequests is null)
            {
                config = config.Replace("\"allowedNetworks\"", "\"dropMalformedRequests\": false,\r\n  \"allowedNetworks\"");

                await File.WriteAllTextAsync(Path.Combine(dnsServer.ApplicationFolder, "dnsApp.config"), config);
            }
        }

        public Task<DnsRequestControllerAction> GetRequestActionAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol)
        {
            if (!_enableBlocking)
                return Task.FromResult(DnsRequestControllerAction.Allow);

            if (_dropMalformedRequests && (request.ParsingException is not null))
                return Task.FromResult(DnsRequestControllerAction.DropSilently);

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

            if (request.Question.Count != 1)
                return Task.FromResult(DnsRequestControllerAction.DropSilently);

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
            readonly DnsResourceRecordType _type;

            #endregion

            #region constructor

            public BlockedQuestion(dynamic jsonQuestion)
            {
                _name = jsonQuestion.name?.Value;

                string strType = jsonQuestion.type?.Value;
                if (!string.IsNullOrEmpty(strType) && Enum.TryParse(strType, true, out DnsResourceRecordType type))
                    _type = type;
                else
                    _type = DnsResourceRecordType.Unknown;
            }

            #endregion

            #region public

            public bool Matches(DnsQuestionRecord question)
            {
                if ((_name is not null) && !_name.Equals(question.Name, StringComparison.OrdinalIgnoreCase))
                    return false;

                if ((_type != DnsResourceRecordType.Unknown) && (_type != question.Type))
                    return false;

                return true;
            }

            #endregion
        }
    }
}
