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

using DnsServerCore.Dns.Dnssec;
using DnsServerCore.Dns.ResourceRecords;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns.Zones
{
    //Message Digest for DNS Zones
    //https://datatracker.ietf.org/doc/rfc8976/

    class SecondaryZone : ApexZone
    {
        #region variables

        IReadOnlyCollection<DnssecPrivateKey> _dnssecPrivateKeys; //for holding DNSSEC private keys as a backup on secondary cluster nodes

        readonly object _refreshTimerLock = new object();
        Timer _refreshTimer;
        bool _refreshTimerTriggered;
        const int REFRESH_TIMER_INTERVAL = 5000;

        const int REFRESH_SOA_TIMEOUT = 10000;
        const int REFRESH_XFR_TIMEOUT = 120000;
        const int REFRESH_RETRIES = 5;

        const int REFRESH_TSIG_FUDGE = 300;

        bool _overrideCatalogPrimaryNameServers;

        IReadOnlyList<NameServerAddress> _primaryNameServerAddresses;
        DnsTransportProtocol _primaryZoneTransferProtocol;
        string _primaryZoneTransferTsigKeyName;

        DateTime _expiry;
        bool _isExpired;

        bool _validateZone;
        bool _validationFailed;

        bool _resync;

        #endregion

        #region constructor

        public SecondaryZone(DnsServer dnsServer, AuthZoneInfo zoneInfo)
            : base(dnsServer, zoneInfo)
        {
            _dnssecPrivateKeys = zoneInfo.DnssecPrivateKeys;

            _overrideCatalogPrimaryNameServers = zoneInfo.OverrideCatalogPrimaryNameServers;

            _primaryNameServerAddresses = zoneInfo.PrimaryNameServerAddresses;
            _primaryZoneTransferProtocol = zoneInfo.PrimaryZoneTransferProtocol;
            _primaryZoneTransferTsigKeyName = zoneInfo.PrimaryZoneTransferTsigKeyName;

            _expiry = zoneInfo.Expiry;
            _isExpired = DateTime.UtcNow > _expiry;

            _validateZone = zoneInfo.ValidateZone;
            _validationFailed = zoneInfo.ValidationFailed;

            _refreshTimer = new Timer(RefreshTimerCallback, null, Timeout.Infinite, Timeout.Infinite);

            InitNotify();
        }

        protected SecondaryZone(DnsServer dnsServer, string name, IReadOnlyList<NameServerAddress> primaryNameServerAddresses, DnsTransportProtocol primaryZoneTransferProtocol, string primaryZoneTransferTsigKeyName, bool validateZone)
            : base(dnsServer, name)
        {
            PrimaryZoneTransferProtocol = primaryZoneTransferProtocol;

            PrimaryNameServerAddresses = primaryNameServerAddresses?.Convert(delegate (NameServerAddress nameServer)
            {
                if (nameServer.Protocol != primaryZoneTransferProtocol)
                    nameServer = nameServer.ChangeProtocol(primaryZoneTransferProtocol);

                return nameServer;
            });

            PrimaryZoneTransferTsigKeyName = primaryZoneTransferTsigKeyName;
            _validateZone = validateZone;

            _isExpired = true; //new secondary zone is considered expired till it refreshes

            _refreshTimer = new Timer(RefreshTimerCallback, null, Timeout.Infinite, Timeout.Infinite);

            InitNotify();
        }

        #endregion

        #region static

        public static async Task<SecondaryZone> CreateAsync(DnsServer dnsServer, string name, IReadOnlyList<NameServerAddress> primaryNameServerAddresses = null, DnsTransportProtocol primaryZoneTransferProtocol = DnsTransportProtocol.Tcp, string primaryZoneTransferTsigKeyName = null, bool validateZone = false, bool ignoreSoaFailure = false)
        {
            SecondaryZone secondaryZone = new SecondaryZone(dnsServer, name, primaryNameServerAddresses, primaryZoneTransferProtocol, primaryZoneTransferTsigKeyName, validateZone);

            try
            {
                DnsDatagram soaResponse;

                DnsQuestionRecord soaQuestion = new DnsQuestionRecord(secondaryZone._name, DnsResourceRecordType.SOA, DnsClass.IN);

                if (secondaryZone.PrimaryNameServerAddresses is null)
                {
                    soaResponse = await secondaryZone._dnsServer.DirectQueryAsync(soaQuestion);
                }
                else
                {
                    DnsClient dnsClient = new DnsClient(secondaryZone.PrimaryNameServerAddresses);
                    List<Task> tasks = new List<Task>(dnsClient.Servers.Count);

                    foreach (NameServerAddress nameServerAddress in dnsClient.Servers)
                    {
                        if (nameServerAddress.IsIPEndPointStale)
                            tasks.Add(nameServerAddress.ResolveIPAddressAsync(secondaryZone._dnsServer, secondaryZone._dnsServer.PreferIPv6));
                    }

                    await Task.WhenAll(tasks);

                    dnsClient.Proxy = secondaryZone._dnsServer.Proxy;
                    dnsClient.PreferIPv6 = secondaryZone._dnsServer.PreferIPv6;

                    DnsDatagram soaRequest = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.NoError, [soaQuestion], null, null, null, secondaryZone._dnsServer.UdpPayloadSize);

                    if (string.IsNullOrEmpty(primaryZoneTransferTsigKeyName))
                        soaResponse = await dnsClient.RawResolveAsync(soaRequest);
                    else if ((secondaryZone._dnsServer.TsigKeys is not null) && secondaryZone._dnsServer.TsigKeys.TryGetValue(primaryZoneTransferTsigKeyName, out TsigKey key))
                        soaResponse = await dnsClient.TsigResolveAsync(soaRequest, key, REFRESH_TSIG_FUDGE);
                    else
                        throw new DnsServerException("No such TSIG key was found configured: " + primaryZoneTransferTsigKeyName);
                }

                if ((soaResponse.Answer.Count == 0) || (soaResponse.Answer[0].Type != DnsResourceRecordType.SOA))
                    throw new DnsServerException("DNS Server did not receive SOA record in response from any of the primary name servers for: " + secondaryZone.ToString());

                DnsResourceRecord receivedSoaRecord = soaResponse.Answer[0];
                DnsSOARecordData receivedSoa = receivedSoaRecord.RDATA as DnsSOARecordData;

                DnsSOARecordData soa = new DnsSOARecordData(receivedSoa.PrimaryNameServer, receivedSoa.ResponsiblePerson, 0u, receivedSoa.Refresh, receivedSoa.Retry, receivedSoa.Expire, receivedSoa.Minimum);
                DnsResourceRecord soaRecord = new DnsResourceRecord(secondaryZone._name, DnsResourceRecordType.SOA, DnsClass.IN, receivedSoaRecord.OriginalTtlValue, soa);

                secondaryZone._entries[DnsResourceRecordType.SOA] = [soaRecord];
            }
            catch
            {
                if (!ignoreSoaFailure)
                    throw;

                //continue with dummy SOA
                DnsSOARecordData soa = new DnsSOARecordData(secondaryZone._dnsServer.ServerDomain, "invalid", 0, 300, 60, 604800, 900);
                DnsResourceRecord soaRecord = new DnsResourceRecord(secondaryZone._name, DnsResourceRecordType.SOA, DnsClass.IN, 0, soa);
                soaRecord.GetAuthGenericRecordInfo().LastModified = DateTime.UtcNow;

                secondaryZone._entries[DnsResourceRecordType.SOA] = [soaRecord];
            }

            return secondaryZone;
        }

        #endregion

        #region IDisposable

        bool _disposed;

        protected override void Dispose(bool disposing)
        {
            try
            {
                if (_disposed)
                    return;

                if (disposing)
                {
                    lock (_refreshTimerLock)
                    {
                        if (_refreshTimer != null)
                        {
                            _refreshTimer.Dispose();
                            _refreshTimer = null;
                        }
                    }
                }

                _disposed = true;
            }
            finally
            {
                base.Dispose(disposing);
            }
        }

        #endregion

        #region private

        private void RefreshTimerCallback(object state)
        {
            //refresh zone in DNS server's resolver thread pool
            if (!_dnsServer.TryQueueResolverTask(async delegate (object state)
                {
                    try
                    {
                        if (Disabled && !_resync)
                            return;

                        _isExpired = DateTime.UtcNow > _expiry;

                        //get primary name server addresses
                        IReadOnlyList<NameServerAddress> primaryNameServerAddresses;
                        DnsTransportProtocol primaryZoneTransferProtocol;
                        string primaryZoneTransferTsigKeyName;

                        SecondaryCatalogZone secondaryCatalogZone = SecondaryCatalogZone;

                        if ((secondaryCatalogZone is not null) && !_overrideCatalogPrimaryNameServers)
                        {
                            primaryNameServerAddresses = await GetResolvedNameServerAddressesAsync(secondaryCatalogZone.PrimaryNameServerAddresses);
                            primaryZoneTransferProtocol = secondaryCatalogZone.PrimaryZoneTransferProtocol;
                            primaryZoneTransferTsigKeyName = secondaryCatalogZone.PrimaryZoneTransferTsigKeyName;
                        }
                        else
                        {
                            primaryNameServerAddresses = await GetResolvedPrimaryNameServerAddressesAsync();
                            primaryZoneTransferProtocol = _primaryZoneTransferProtocol;
                            primaryZoneTransferTsigKeyName = _primaryZoneTransferTsigKeyName;
                        }

                        DnsResourceRecord currentSoaRecord = _entries[DnsResourceRecordType.SOA][0];
                        DnsSOARecordData currentSoa = currentSoaRecord.RDATA as DnsSOARecordData;

                        if (primaryNameServerAddresses.Count == 0)
                        {
                            _dnsServer.LogManager.Write("DNS Server could not find primary name server IP addresses for " + GetZoneTypeName() + " zone: " + ToString());

                            //set timer for retry
                            ResetRefreshTimer(Math.Max(currentSoa.Retry, _dnsServer.AuthZoneManager.MinSoaRetry) * 1000);
                            _syncFailed = true;
                            return;
                        }

                        TsigKey key = null;

                        if (!string.IsNullOrEmpty(primaryZoneTransferTsigKeyName) && ((_dnsServer.TsigKeys is null) || !_dnsServer.TsigKeys.TryGetValue(primaryZoneTransferTsigKeyName, out key)))
                        {
                            _dnsServer.LogManager.Write("DNS Server does not have TSIG key '" + primaryZoneTransferTsigKeyName + "' configured for refreshing " + GetZoneTypeName() + " zone: " + ToString());

                            //set timer for retry
                            ResetRefreshTimer(Math.Max(currentSoa.Retry, _dnsServer.AuthZoneManager.MinSoaRetry) * 1000);
                            _syncFailed = true;
                            return;
                        }

                        //refresh zone
                        if (await RefreshZoneAsync(primaryNameServerAddresses, primaryZoneTransferProtocol, key, _validateZone))
                        {
                            DnsSOARecordData latestSoa = _entries[DnsResourceRecordType.SOA][0].RDATA as DnsSOARecordData;

                            _syncFailed = false;
                            _expiry = DateTime.UtcNow.AddSeconds(latestSoa.Expire);
                            _isExpired = false;
                            _resync = false;
                            _dnsServer.AuthZoneManager.SaveZoneFile(_name);

                            if (_validationFailed)
                                ResetRefreshTimer(Math.Max(latestSoa.Retry, _dnsServer.AuthZoneManager.MinSoaRetry) * 1000); //zone validation failed, set timer for retry
                            else
                                ResetRefreshTimer(Math.Max(latestSoa.Refresh, _dnsServer.AuthZoneManager.MinSoaRefresh) * 1000); //zone refreshed; set timer for refresh

                            return;
                        }

                        //no response from any of the name servers; set timer for retry
                        ResetRefreshTimer(Math.Max(GetZoneSoaRetry(), _dnsServer.AuthZoneManager.MinSoaRetry) * 1000);
                        _syncFailed = true;
                    }
                    catch (Exception ex)
                    {
                        _dnsServer.LogManager.Write(ex);

                        //set timer for retry
                        ResetRefreshTimer(Math.Max(GetZoneSoaRetry(), _dnsServer.AuthZoneManager.MinSoaRetry) * 1000);
                        _syncFailed = true;
                    }
                    finally
                    {
                        _refreshTimerTriggered = false;
                    }
                })
            )
            {
                //failed to queue refresh zone task; try again in some time
                _refreshTimer?.Change(REFRESH_TIMER_INTERVAL, Timeout.Infinite);
            }
        }

        private void ResetRefreshTimer(long dueTime)
        {
            lock (_refreshTimerLock)
            {
                _refreshTimer?.Change(dueTime, Timeout.Infinite);
            }
        }

        private async Task<bool> RefreshZoneAsync(IReadOnlyList<NameServerAddress> primaryNameServers, DnsTransportProtocol zoneTransferProtocol, TsigKey key, bool validateZone)
        {
            try
            {
                _dnsServer.LogManager.Write("DNS Server has started zone refresh for " + GetZoneTypeName() + " zone: " + ToString());

                //get nameservers list with correct zone tranfer protocol
                List<NameServerAddress> updatedNameServers = new List<NameServerAddress>(primaryNameServers.Count);
                {
                    switch (zoneTransferProtocol)
                    {
                        case DnsTransportProtocol.Tls:
                        case DnsTransportProtocol.Quic:
                            //change name server protocol to TLS/QUIC
                            foreach (NameServerAddress primaryNameServer in primaryNameServers)
                            {
                                if (primaryNameServer.Protocol == zoneTransferProtocol)
                                    updatedNameServers.Add(primaryNameServer);
                                else
                                    updatedNameServers.Add(primaryNameServer.ChangeProtocol(zoneTransferProtocol));
                            }

                            break;

                        default:
                            //change name server protocol to TCP
                            foreach (NameServerAddress primaryNameServer in primaryNameServers)
                            {
                                if (primaryNameServer.Protocol == DnsTransportProtocol.Tcp)
                                    updatedNameServers.Add(primaryNameServer);
                                else
                                    updatedNameServers.Add(primaryNameServer.ChangeProtocol(DnsTransportProtocol.Tcp));
                            }

                            break;
                    }
                }

                //init XFR DNS Client
                DnsClient xfrClient = new DnsClient(updatedNameServers);
                xfrClient.Proxy = _dnsServer.Proxy;
                xfrClient.PreferIPv6 = _dnsServer.PreferIPv6;
                xfrClient.Retries = REFRESH_RETRIES;
                xfrClient.Concurrency = 1;

                DnsResourceRecord currentSoaRecord = _entries[DnsResourceRecordType.SOA][0];
                DnsSOARecordData currentSoa = currentSoaRecord.RDATA as DnsSOARecordData;

                if (!_resync && (this is not SecondaryForwarderZone)) //skip SOA probe for Secondary Forwarder/Catalog since Forwarder/Catalog is not authoritative for SOA
                {
                    //check for update
                    xfrClient.Timeout = REFRESH_SOA_TIMEOUT;

                    DnsDatagram soaRequest = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.NoError, [new DnsQuestionRecord(_name, DnsResourceRecordType.SOA, DnsClass.IN)], null, null, null, _dnsServer.UdpPayloadSize);
                    DnsDatagram soaResponse;

                    if (key is null)
                        soaResponse = await xfrClient.RawResolveAsync(soaRequest);
                    else
                        soaResponse = await xfrClient.TsigResolveAsync(soaRequest, key, REFRESH_TSIG_FUDGE);

                    if (soaResponse.RCODE != DnsResponseCode.NoError)
                    {
                        _dnsServer.LogManager.Write("DNS Server received RCODE=" + soaResponse.RCODE.ToString() + " for '" + ToString() + "' " + GetZoneTypeName() + " zone refresh from: " + soaResponse.Metadata.NameServer.ToString());
                        return false;
                    }

                    if ((soaResponse.Answer.Count < 1) || (soaResponse.Answer[0].Type != DnsResourceRecordType.SOA) || !_name.Equals(soaResponse.Answer[0].Name, StringComparison.OrdinalIgnoreCase))
                    {
                        _dnsServer.LogManager.Write("DNS Server received an empty response for SOA query for '" + ToString() + "' " + GetZoneTypeName() + " zone refresh from: " + soaResponse.Metadata.NameServer.ToString());
                        return false;
                    }

                    DnsResourceRecord receivedSoaRecord = soaResponse.Answer[0];
                    DnsSOARecordData receivedSoa = receivedSoaRecord.RDATA as DnsSOARecordData;

                    //compare using sequence space arithmetic
                    if (!currentSoa.IsZoneUpdateAvailable(receivedSoa))
                    {
                        _dnsServer.LogManager.Write("DNS Server successfully checked for '" + ToString() + "' " + GetZoneTypeName() + " zone update from: " + soaResponse.Metadata.NameServer.ToString());
                        return true;
                    }
                }

                //update available; do zone transfer
                xfrClient.Timeout = REFRESH_XFR_TIMEOUT;

                bool doIXFR = !_isExpired && !_resync;

                while (true)
                {
                    DnsQuestionRecord xfrQuestion;
                    IReadOnlyList<DnsResourceRecord> xfrAuthority;

                    if (doIXFR)
                    {
                        xfrQuestion = new DnsQuestionRecord(_name, DnsResourceRecordType.IXFR, DnsClass.IN);
                        xfrAuthority = [currentSoaRecord];
                    }
                    else
                    {
                        xfrQuestion = new DnsQuestionRecord(_name, DnsResourceRecordType.AXFR, DnsClass.IN);
                        xfrAuthority = null;
                    }

                    DnsDatagram xfrRequest = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.NoError, [xfrQuestion], null, xfrAuthority);
                    DnsDatagram xfrResponse;

                    if (key is null)
                        xfrResponse = await xfrClient.RawResolveAsync(xfrRequest);
                    else
                        xfrResponse = await xfrClient.TsigResolveAsync(xfrRequest, key, REFRESH_TSIG_FUDGE);

                    if (doIXFR && ((xfrResponse.RCODE == DnsResponseCode.NotImplemented) || (xfrResponse.RCODE == DnsResponseCode.Refused)))
                    {
                        doIXFR = false;
                        continue;
                    }

                    if (xfrResponse.RCODE != DnsResponseCode.NoError)
                    {
                        _dnsServer.LogManager.Write("DNS Server received a zone transfer response (RCODE=" + xfrResponse.RCODE.ToString() + ") for '" + ToString() + "' " + GetZoneTypeName() + " zone from: " + xfrResponse.Metadata.NameServer.ToString());
                        return false;
                    }

                    if (xfrResponse.Answer.Count < 1)
                    {
                        _dnsServer.LogManager.Write("DNS Server received an empty response for zone transfer query for '" + ToString() + "' " + GetZoneTypeName() + " zone from: " + xfrResponse.Metadata.NameServer.ToString());
                        return false;
                    }

                    if (!_name.Equals(xfrResponse.Answer[0].Name, StringComparison.OrdinalIgnoreCase) || (xfrResponse.Answer[0].RDATA is not DnsSOARecordData xfrSoa))
                    {
                        _dnsServer.LogManager.Write("DNS Server received invalid response for zone transfer query for '" + ToString() + "' " + GetZoneTypeName() + " zone from: " + xfrResponse.Metadata.NameServer.ToString());
                        return false;
                    }

                    if (_resync || currentSoa.IsZoneUpdateAvailable(xfrSoa))
                    {
                        xfrResponse = xfrResponse.Join(); //join multi message response

                        if (doIXFR)
                        {
                            IReadOnlyList<DnsResourceRecord> historyRecords = _dnsServer.AuthZoneManager.SyncIncrementalZoneTransferRecords(_name, xfrResponse.Answer);
                            if (historyRecords.Count > 0)
                                await FinalizeIncrementalZoneTransferAsync(historyRecords);
                            else
                                await FinalizeZoneTransferAsync(); //AXFR response was received
                        }
                        else
                        {
                            _dnsServer.AuthZoneManager.SyncZoneTransferRecords(_name, xfrResponse.Answer);
                            await FinalizeZoneTransferAsync();
                        }

                        _lastModified = DateTime.UtcNow;

                        if (validateZone)
                            await ValidateZoneAsync();
                        else
                            _validationFailed = false;

                        if (_validationFailed)
                        {
                            _dnsServer.LogManager.Write("DNS Server refreshed '" + ToString() + "' " + GetZoneTypeName() + " zone with validation failure from: " + xfrResponse.Metadata.NameServer.ToString());
                        }
                        else
                        {
                            //trigger notify
                            TriggerNotify();

                            _dnsServer.LogManager.Write("DNS Server successfully refreshed '" + ToString() + "' " + GetZoneTypeName() + " zone from: " + xfrResponse.Metadata.NameServer.ToString());
                        }
                    }
                    else
                    {
                        _dnsServer.LogManager.Write("DNS Server successfully checked for '" + ToString() + "' " + GetZoneTypeName() + " zone update from: " + xfrResponse.Metadata.NameServer.ToString());
                    }

                    return true;
                }
            }
            catch (Exception ex)
            {
                _dnsServer.LogManager.Write("DNS Server failed to refresh '" + ToString() + "' " + GetZoneTypeName() + " zone from: " + primaryNameServers.Join() + "\r\n" + ex.ToString());

                return false;
            }
        }

        private async Task ValidateZoneAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                DirectDnsClient dnsClient = new DirectDnsClient(_dnsServer);
                dnsClient.DnssecValidation = true;
                dnsClient.Timeout = 10000;

                DnsDatagram zoneMdResponse = await dnsClient.ResolveAsync(_name, DnsResourceRecordType.ZONEMD, cancellationToken);
                IReadOnlyList<DnsZONEMDRecordData> zoneMdList = DnsClient.ParseResponseZONEMD(zoneMdResponse);
                if (zoneMdList.Count == 0)
                {
                    //ZONEMD RRSet does not exists; digest verification cannot occur
                    _validationFailed = false;
                    _dnsServer.LogManager.Write("ZONEMD validation cannot occur for the " + GetZoneTypeName() + " zone '" + ToString() + "': ZONEMD RRset does not exists in the zone.");
                    return;
                }

                for (int i = 0; i < zoneMdList.Count; i++)
                {
                    for (int j = 0; j < zoneMdList.Count; j++)
                    {
                        if (i == j)
                            continue; //skip comparing self

                        DnsZONEMDRecordData zoneMd = zoneMdList[i];
                        DnsZONEMDRecordData checkZoneMd = zoneMdList[j];

                        if ((checkZoneMd.Scheme == zoneMd.Scheme) && (checkZoneMd.HashAlgorithm == zoneMd.HashAlgorithm))
                        {
                            _validationFailed = true;
                            _dnsServer.LogManager.Write("ZONEMD validation failed for the " + GetZoneTypeName() + " zone '" + ToString() + "': ZONEMD RRset contains more than one RR with the same Scheme and Hash Algorithm.");
                            return;
                        }
                    }
                }

                DnsDatagram soaResponse = await dnsClient.ResolveAsync(_name, DnsResourceRecordType.SOA, cancellationToken);
                DnsSOARecordData soa = DnsClient.ParseResponseSOA(soaResponse);
                if (soa is null)
                {
                    _validationFailed = true;
                    _dnsServer.LogManager.Write("ZONEMD validation failed for the " + GetZoneTypeName() + " zone '" + ToString() + "': failed to find SOA record.");
                    return;
                }

                using MemoryStream hashStream = new MemoryStream(4096);
                byte[] computedDigestSHA384 = null;
                byte[] computedDigestSHA512 = null;
                bool zoneSerialized = false;

                foreach (DnsZONEMDRecordData zoneMd in zoneMdList)
                {
                    if (soa.Serial != zoneMd.Serial)
                        continue;

                    if (zoneMd.Scheme != ZoneMdScheme.Simple)
                        continue;

                    byte[] computedDigest;

                    switch (zoneMd.HashAlgorithm)
                    {
                        case ZoneMdHashAlgorithm.SHA384:
                            if (zoneMd.Digest.Length != 48)
                                continue;

                            if (computedDigestSHA384 is null)
                            {
                                if (!zoneSerialized)
                                {
                                    SerializeZoneTo(hashStream);
                                    zoneSerialized = true;
                                }

                                hashStream.Position = 0;
                                computedDigestSHA384 = SHA384.HashData(hashStream);
                            }

                            computedDigest = computedDigestSHA384;
                            break;

                        case ZoneMdHashAlgorithm.SHA512:
                            if (zoneMd.Digest.Length != 64)
                                continue;

                            if (computedDigestSHA512 is null)
                            {
                                if (!zoneSerialized)
                                {
                                    SerializeZoneTo(hashStream);
                                    zoneSerialized = true;
                                }

                                hashStream.Position = 0;
                                computedDigestSHA512 = SHA512.HashData(hashStream);
                            }

                            computedDigest = computedDigestSHA512;
                            break;

                        default:
                            continue;
                    }

                    if (computedDigest.ListEquals(zoneMd.Digest))
                    {
                        //validation successfull
                        _validationFailed = false;
                        _dnsServer.LogManager.Write("ZONEMD validation was completed successfully for the " + GetZoneTypeName() + " zone: " + ToString());
                        return;
                    }
                }

                //validation failed
                _validationFailed = true;
                _dnsServer.LogManager.Write("ZONEMD validation failed for the " + GetZoneTypeName() + " zone '" + ToString() + "': none of the ZONEMD records could successfully validate the zone.");
            }
            catch (Exception ex)
            {
                //validation failed
                _validationFailed = true;
                _dnsServer.LogManager.Write("ZONEMD validation failed for the " + GetZoneTypeName() + " zone '" + ToString() + "':\r\n" + ex.ToString());
            }
        }

        private void SerializeZoneTo(MemoryStream hashStream)
        {
            //list zone records for ZONEMD Simple scheme
            List<DnsResourceRecord> records;
            {
                List<DnsResourceRecord> allZoneRecords = new List<DnsResourceRecord>();

                _dnsServer.AuthZoneManager.ListAllZoneRecords(_name, allZoneRecords);

                records = new List<DnsResourceRecord>(allZoneRecords.Count);

                foreach (DnsResourceRecord record in allZoneRecords)
                {
                    switch (record.Type)
                    {
                        case DnsResourceRecordType.NS:
                            records.Add(record);

                            IReadOnlyList<DnsResourceRecord> glueRecords = record.GetAuthNSRecordInfo().GlueRecords;
                            if (glueRecords is not null)
                                records.AddRange(glueRecords);

                            break;

                        case DnsResourceRecordType.RRSIG:
                            if (record.Name.Equals(_name, StringComparison.OrdinalIgnoreCase) && (record.RDATA is DnsRRSIGRecordData rdata) && (rdata.TypeCovered == DnsResourceRecordType.ZONEMD))
                                break; //skip RRSIG covering the apex ZONEMD

                            records.Add(record);
                            break;

                        case DnsResourceRecordType.ZONEMD:
                            if (record.Name.Equals(_name, StringComparison.OrdinalIgnoreCase))
                                break; //skip apex ZONEMD

                            records.Add(record);
                            break;

                        default:
                            records.Add(record);
                            break;
                    }
                }
            }

            //group records into zones by DNS name
            List<KeyValuePair<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>>> zones = new List<KeyValuePair<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>>>(DnsResourceRecord.GroupRecords(records, true));

            //sort zones by canonical DNS name
            zones.Sort(delegate (KeyValuePair<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> x, KeyValuePair<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> y)
            {
                return DnsNSECRecordData.CanonicalComparison(x.Key, y.Key);
            });

            //start serialization, zone by zone
            using MemoryStream rrBuffer = new MemoryStream(512);

            foreach (KeyValuePair<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> zone in zones)
            {
                //list all RRSets for current zone owner name
                List<KeyValuePair<DnsResourceRecordType, List<DnsResourceRecord>>> rrSets = new List<KeyValuePair<DnsResourceRecordType, List<DnsResourceRecord>>>(zone.Value);

                //RRsets having the same owner name MUST be numerically ordered, in ascending order, by their numeric RR TYPE
                rrSets.Sort(delegate (KeyValuePair<DnsResourceRecordType, List<DnsResourceRecord>> x, KeyValuePair<DnsResourceRecordType, List<DnsResourceRecord>> y)
                {
                    return x.Key.CompareTo(y.Key);
                });

                //serialize records
                List<CanonicallySerializedResourceRecord> rrList = new List<CanonicallySerializedResourceRecord>(rrSets.Count * 4);

                foreach (KeyValuePair<DnsResourceRecordType, List<DnsResourceRecord>> rrSet in rrSets)
                {
                    //serialize current RRSet records
                    List<CanonicallySerializedResourceRecord> serializedResourceRecords = new List<CanonicallySerializedResourceRecord>(rrSet.Value.Count);

                    foreach (DnsResourceRecord record in rrSet.Value)
                        serializedResourceRecords.Add(CanonicallySerializedResourceRecord.Create(record.Name, record.Type, record.Class, record.OriginalTtlValue, record.RDATA, rrBuffer));

                    //Canonical RR Ordering by sorting RDATA portion of the canonical form of each RR
                    serializedResourceRecords.Sort();

                    foreach (CanonicallySerializedResourceRecord serializedResourceRecord in serializedResourceRecords)
                        serializedResourceRecord.WriteTo(hashStream);
                }
            }
        }

        protected virtual Task FinalizeZoneTransferAsync()
        {
            ClearZoneHistory();

            return Task.CompletedTask;
        }

        protected virtual Task FinalizeIncrementalZoneTransferAsync(IReadOnlyList<DnsResourceRecord> historyRecords)
        {
            CommitZoneHistory(historyRecords);

            return Task.CompletedTask;
        }

        #endregion

        #region public

        public override string GetZoneTypeName()
        {
            return "Secondary";
        }

        public void TriggerRefresh(int refreshInterval = REFRESH_TIMER_INTERVAL)
        {
            if (Disabled)
                return;

            if (_refreshTimerTriggered)
                return;

            _refreshTimerTriggered = true;
            ResetRefreshTimer(refreshInterval);
        }

        public void TriggerResync()
        {
            if (_refreshTimerTriggered)
                return;

            _resync = true;

            _refreshTimerTriggered = true;
            ResetRefreshTimer(0);
        }

        public override void SetRecords(DnsResourceRecordType type, IReadOnlyList<DnsResourceRecord> records)
        {
            throw new InvalidOperationException("Cannot set records in " + GetZoneTypeName() + " zone.");
        }

        public override bool AddRecord(DnsResourceRecord record)
        {
            throw new InvalidOperationException("Cannot add record in " + GetZoneTypeName() + " zone.");
        }

        public override bool DeleteRecord(DnsResourceRecordType type, DnsResourceRecordData record)
        {
            throw new InvalidOperationException("Cannot delete record in " + GetZoneTypeName() + " zone.");
        }

        public override bool DeleteRecords(DnsResourceRecordType type)
        {
            throw new InvalidOperationException("Cannot delete records in " + GetZoneTypeName() + " zone.");
        }

        public override void UpdateRecord(DnsResourceRecord oldRecord, DnsResourceRecord newRecord)
        {
            throw new InvalidOperationException("Cannot update record in " + GetZoneTypeName() + " zone.");
        }

        #endregion

        #region properties

        public override bool Disabled
        {
            get { return base.Disabled; }
            set
            {
                if (base.Disabled == value)
                    return;

                base.Disabled = value; //set value early to be able to use it for notify

                if (value)
                {
                    DisableNotifyTimer();
                    ResetRefreshTimer(Timeout.Infinite);
                }
                else
                {
                    TriggerNotify();
                    TriggerRefresh();
                }
            }
        }

        public override bool OverrideCatalogNotify
        {
            get { throw new InvalidOperationException(); }
            set { throw new InvalidOperationException(); }
        }

        public virtual bool OverrideCatalogPrimaryNameServers
        {
            get { return _overrideCatalogPrimaryNameServers; }
            set { _overrideCatalogPrimaryNameServers = value; }
        }

        public override AuthZoneNotify Notify
        {
            get { return base.Notify; }
            set
            {
                switch (value)
                {
                    case AuthZoneNotify.SeparateNameServersForCatalogAndMemberZones:
                        throw new ArgumentException("The Notify option is invalid for " + GetZoneTypeName() + " zones: " + value.ToString(), nameof(Notify));
                }

                base.Notify = value;
            }
        }

        public override AuthZoneUpdate Update
        {
            get { return base.Update; }
            set
            {
                switch (value)
                {
                    case AuthZoneUpdate.AllowOnlyZoneNameServers:
                    case AuthZoneUpdate.AllowZoneNameServersAndUseSpecifiedNetworkACL:
                        throw new ArgumentException("The Dynamic Updates option is invalid for Secondary zones: " + value.ToString(), nameof(Update));
                }

                base.Update = value;
            }
        }

        public virtual IReadOnlyList<NameServerAddress> PrimaryNameServerAddresses
        {
            get { return _primaryNameServerAddresses; }
            set
            {
                if ((value is null) || (value.Count == 0))
                    _primaryNameServerAddresses = null;
                else if (value.Count > byte.MaxValue)
                    throw new ArgumentOutOfRangeException(nameof(PrimaryNameServerAddresses), "Name server addresses cannot have more than 255 entries.");
                else
                    _primaryNameServerAddresses = value;
            }
        }

        public DnsTransportProtocol PrimaryZoneTransferProtocol
        {
            get { return _primaryZoneTransferProtocol; }
            set
            {
                switch (value)
                {
                    case DnsTransportProtocol.Tcp:
                    case DnsTransportProtocol.Tls:
                    case DnsTransportProtocol.Quic:
                        _primaryZoneTransferProtocol = value;
                        break;

                    default:
                        throw new NotSupportedException("Zone transfer protocol is not supported: XFR-over-" + value.ToString().ToUpper());
                }
            }
        }

        public string PrimaryZoneTransferTsigKeyName
        {
            get { return _primaryZoneTransferTsigKeyName; }
            set
            {
                if (value is null)
                    _primaryZoneTransferTsigKeyName = string.Empty;
                else
                    _primaryZoneTransferTsigKeyName = value;
            }
        }

        public DateTime Expiry
        { get { return _expiry; } }

        public bool IsExpired
        { get { return _isExpired; } }

        public virtual bool ValidateZone
        {
            get { return _validateZone; }
            set { _validateZone = value; }
        }

        public bool ValidationFailed
        { get { return _validationFailed; } }

        public override bool IsActive
        {
            get { return !Disabled && !_isExpired && !_validationFailed; }
        }

        public IReadOnlyCollection<DnssecPrivateKey> DnssecPrivateKeys
        {
            get { return _dnssecPrivateKeys; }
            set { _dnssecPrivateKeys = value; }
        }

        #endregion
    }
}
