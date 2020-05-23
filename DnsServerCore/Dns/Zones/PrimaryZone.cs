using System;
using System.Collections.Generic;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Dns.Zones
{
    public sealed class PrimaryZone : AuthZone
    {
        #region variables

        readonly bool _internal;

        #endregion

        #region constructor

        public PrimaryZone(string name, DnsSOARecord soa, bool @internal)
            : base(name, soa)
        {
            _internal = @internal;
        }

        public PrimaryZone(string name, DnsSOARecord soa, DnsNSRecord ns, bool @internal)
            : base(name, soa, ns)
        {
            _internal = @internal;
        }

        public PrimaryZone(string name, bool disabled)
            : base(name)
        {
            _disabled = disabled;
        }

        #endregion

        #region public

        public override void SetRecords(DnsResourceRecordType type, IReadOnlyList<DnsResourceRecord> records)
        {
            if (type == DnsResourceRecordType.CNAME)
                throw new InvalidOperationException("Cannot add CNAME record to zone root.");

            base.SetRecords(type, records);
        }

        #endregion

        #region properties

        public bool Internal
        { get { return _internal; } }

        #endregion
    }
}
