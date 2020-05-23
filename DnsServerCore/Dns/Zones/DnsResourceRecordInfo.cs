using System;
using System.Collections.Generic;
using System.IO;
using TechnitiumLibrary.Net.Dns;

namespace DnsServerCore.Dns.Zones
{
    public class DnsResourceRecordInfo
    {
        #region variables

        bool _disabled;
        IReadOnlyList<DnsResourceRecord> _glueRecords;

        #endregion

        #region constructor

        public DnsResourceRecordInfo()
        { }

        public DnsResourceRecordInfo(BinaryReader bR)
        {
            switch (bR.ReadByte()) //version
            {
                case 1:
                    _disabled = bR.ReadBoolean();
                    break;

                case 2:
                    _disabled = bR.ReadBoolean();

                    DnsResourceRecord[] glueRecords = new DnsResourceRecord[bR.ReadByte()];

                    for (int i = 0; i < glueRecords.Length; i++)
                        glueRecords[i] = new DnsResourceRecord(bR.BaseStream);

                    _glueRecords = glueRecords;
                    break;

                default:
                    throw new InvalidDataException("DnsResourceRecordInfo format version not supported.");
            }
        }

        #endregion

        #region public

        public void WriteTo(BinaryWriter bW)
        {
            bW.Write((byte)2); //version
            bW.Write(_disabled);

            if (_glueRecords == null)
            {
                bW.Write((byte)0);
            }
            else
            {
                bW.Write(Convert.ToByte(_glueRecords.Count));

                foreach (DnsResourceRecord glueRecord in _glueRecords)
                    glueRecord.WriteTo(bW.BaseStream);
            }
        }

        #endregion

        #region properties

        public bool Disabled
        {
            get { return _disabled; }
            set { _disabled = value; }
        }

        public IReadOnlyList<DnsResourceRecord> GlueRecords
        {
            get { return _glueRecords; }
            set { _glueRecords = value; }
        }

        #endregion
    }
}
