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

using DnsServerCore.Dns.Zones;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns.ZoneManagers
{
    public sealed class BlockedZoneManager
    {
        #region variables

        readonly DnsServer _dnsServer;

        readonly AuthZoneManager _zoneManager;

        DnsSOARecordData _soaRecord;
        DnsNSRecordData _nsRecord;

        readonly object _saveLock = new object();
        bool _pendingSave;
        readonly Timer _saveTimer;
        const int SAVE_TIMER_INITIAL_INTERVAL = 10000;

        #endregion

        #region constructor

        public BlockedZoneManager(DnsServer dnsServer)
        {
            _dnsServer = dnsServer;

            _zoneManager = new AuthZoneManager(_dnsServer);

            UpdateServerDomain();

            _saveTimer = new Timer(delegate (object state)
            {
                lock (_saveLock)
                {
                    if (_pendingSave)
                    {
                        try
                        {
                            SaveZoneFileInternal();
                            _pendingSave = false;
                        }
                        catch (Exception ex)
                        {
                            _dnsServer.LogManager.Write(ex);

                            //set timer to retry again
                            _saveTimer.Change(SAVE_TIMER_INITIAL_INTERVAL, Timeout.Infinite);
                        }
                    }
                }
            });
        }

        #endregion

        #region IDisposable

        bool _disposed;

        public void Dispose()
        {
            if (_disposed)
                return;

            lock (_saveLock)
            {
                _saveTimer?.Dispose();

                if (_pendingSave)
                {
                    try
                    {
                        SaveZoneFileInternal();
                    }
                    catch (Exception ex)
                    {
                        _dnsServer.LogManager.Write(ex);
                    }
                    finally
                    {
                        _pendingSave = false;
                    }
                }
            }

            _disposed = true;
        }

        #endregion

        #region private

        internal void UpdateServerDomain()
        {
            _soaRecord = new DnsSOARecordData(_dnsServer.ServerDomain, _dnsServer.ResponsiblePerson.Address, 1, 900, 300, 604800, 60);
            _nsRecord = new DnsNSRecordData(_dnsServer.ServerDomain);

            _zoneManager.UpdateServerDomain();
        }

        private void SaveZoneFileInternal()
        {
            IReadOnlyList<AuthZoneInfo> blockedZones = _dnsServer.BlockedZoneManager.GetAllZones();

            string blockedZoneFile = Path.Combine(_dnsServer.ConfigFolder, "blocked.config");

            using (FileStream fS = new FileStream(blockedZoneFile, FileMode.Create, FileAccess.Write))
            {
                BinaryWriter bW = new BinaryWriter(fS);

                bW.Write(Encoding.ASCII.GetBytes("BZ")); //format
                bW.Write((byte)1); //version

                bW.Write(blockedZones.Count);

                foreach (AuthZoneInfo zone in blockedZones)
                    bW.WriteShortString(zone.Name);
            }

            _dnsServer.LogManager?.Write("DNS Server blocked zone file was saved: " + blockedZoneFile);
        }

        #endregion

        #region public

        public void LoadBlockedZoneFile()
        {
            _zoneManager.Flush();

            string blockedZoneFile = Path.Combine(_dnsServer.ConfigFolder, "blocked.config");

            try
            {
                string oldCustomBlockedZoneFile = Path.Combine(_dnsServer.ConfigFolder, "custom-blocked.config");
                if (File.Exists(oldCustomBlockedZoneFile))
                {
                    if (File.Exists(blockedZoneFile))
                        File.Delete(blockedZoneFile);

                    File.Move(oldCustomBlockedZoneFile, blockedZoneFile);
                }
            }
            catch (Exception ex)
            {
                _dnsServer.LogManager?.Write(ex);
            }

            try
            {
                _dnsServer.LogManager?.Write("DNS Server is loading blocked zone file: " + blockedZoneFile);

                using (FileStream fS = new FileStream(blockedZoneFile, FileMode.Open, FileAccess.Read))
                {
                    BinaryReader bR = new BinaryReader(fS);

                    if (Encoding.ASCII.GetString(bR.ReadBytes(2)) != "BZ") //format
                        throw new InvalidDataException("DnsServer blocked zone file format is invalid.");

                    byte version = bR.ReadByte();
                    switch (version)
                    {
                        case 1:
                            int length = bR.ReadInt32();
                            int i = 0;

                            _zoneManager.LoadSpecialPrimaryZones(delegate ()
                            {
                                if (i++ < length)
                                    return bR.ReadShortString();

                                return null;
                            }, _soaRecord, _nsRecord);

                            break;

                        default:
                            throw new InvalidDataException("DnsServer blocked zone file version not supported.");
                    }
                }

                _dnsServer.LogManager?.Write("DNS Server blocked zone file was loaded: " + blockedZoneFile);
            }
            catch (FileNotFoundException)
            { }
            catch (Exception ex)
            {
                _dnsServer.LogManager?.Write("DNS Server encountered an error while loading blocked zone file: " + blockedZoneFile + "\r\n" + ex.ToString());
            }
        }

        public void ImportZones(string[] domains)
        {
            _zoneManager.LoadSpecialPrimaryZones(domains, _soaRecord, _nsRecord);
        }

        public bool BlockZone(string domain)
        {
            if (_zoneManager.CreateSpecialPrimaryZone(domain, _soaRecord, _nsRecord) != null)
                return true;

            return false;
        }

        public bool DeleteZone(string domain)
        {
            if (_zoneManager.DeleteZone(domain))
                return true;

            return false;
        }

        public void Flush()
        {
            _zoneManager.Flush();
        }

        public IReadOnlyList<AuthZoneInfo> GetAllZones()
        {
            return _zoneManager.GetAllZones();
        }

        public void ListAllRecords(string domain, List<DnsResourceRecord> records)
        {
            _zoneManager.ListAllRecords(domain, domain, records);
        }

        public void ListSubDomains(string domain, List<string> subDomains)
        {
            _zoneManager.ListSubDomains(domain, subDomains);
        }

        public void SaveZoneFile()
        {
            lock (_saveLock)
            {
                if (_pendingSave)
                    return;

                _pendingSave = true;
                _saveTimer.Change(SAVE_TIMER_INITIAL_INTERVAL, Timeout.Infinite);
            }
        }

        public DnsDatagram Query(DnsDatagram request)
        {
            if (_zoneManager.TotalZones < 1)
                return null;

            return _zoneManager.Query(request, false);
        }

        #endregion

        #region properties

        internal DnsSOARecordData DnsSOARecord
        { get { return _soaRecord; } }

        public int TotalZonesBlocked
        { get { return _zoneManager.TotalZones; } }

        #endregion
    }
}
