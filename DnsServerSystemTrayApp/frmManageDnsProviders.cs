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
using System.Net;
using System.Net.Sockets;
using System.Windows.Forms;

namespace DnsServerSystemTrayApp
{
    public partial class frmManageDnsProviders : Form
    {
        #region variables

        static readonly char[] commaSeparator = new char[] { ',' };

        readonly List<DnsProvider> _dnsProviders = new List<DnsProvider>();

        #endregion

        #region constructor

        public frmManageDnsProviders(ICollection<DnsProvider> dnsProviders)
        {
            InitializeComponent();

            _dnsProviders.AddRange(dnsProviders);
        }

        #endregion

        #region private

        private void RefreshDnsProvidersList()
        {
            listView1.SuspendLayout();

            listView1.Items.Clear();

            foreach (DnsProvider dnsProvider in _dnsProviders)
            {
                ListViewItem item = listView1.Items.Add(dnsProvider.Name);
                item.SubItems.Add(dnsProvider.GetIpv4Addresses());
                item.SubItems.Add(dnsProvider.GetIpv6Addresses());

                item.Tag = dnsProvider;
            }

            listView1.ResumeLayout();
        }

        private void ClearForm()
        {
            txtDnsProviderName.Text = "";
            txtIpv4Addresses.Text = "";
            txtIpv6Addresses.Text = "";
            btnAddUpdate.Text = "Add";
            btnDelete.Enabled = false;
        }

        private void frmManageDnsProviders_Load(object sender, EventArgs e)
        {
            RefreshDnsProvidersList();
        }

        private void listView1_SelectedIndexChanged(object sender, EventArgs e)
        {
            if (listView1.SelectedItems.Count > 0)
            {
                ListViewItem selectedItem = listView1.SelectedItems[0];

                txtDnsProviderName.Text = selectedItem.Text;
                txtIpv4Addresses.Text = selectedItem.SubItems[1].Text;
                txtIpv6Addresses.Text = selectedItem.SubItems[2].Text;
                btnAddUpdate.Text = "&Update";
                btnDelete.Enabled = true;
            }
            else
            {
                ClearForm();
            }
        }

        private void btnAddUpdate_Click(object sender, EventArgs e)
        {
            if (string.IsNullOrWhiteSpace(txtDnsProviderName.Text))
            {
                MessageBox.Show("Please enter a valid DNS Provider name.", "Missing DNS Provider!", MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
                return;
            }

            List<IPAddress> addresses = new List<IPAddress>();

            foreach (string item in txtIpv4Addresses.Text.Split(commaSeparator, StringSplitOptions.RemoveEmptyEntries))
            {
                if (IPAddress.TryParse(item.Trim(), out IPAddress address) && (address.AddressFamily == AddressFamily.InterNetwork))
                {
                    addresses.Add(address);
                }
                else
                {
                    MessageBox.Show("Please enter a valid IPv4 address.", "Invalid IPv4 Address!", MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
                    return;
                }
            }

            foreach (string item in txtIpv6Addresses.Text.Split(commaSeparator, StringSplitOptions.RemoveEmptyEntries))
            {
                if (IPAddress.TryParse(item.Trim(), out IPAddress address) && (address.AddressFamily == AddressFamily.InterNetworkV6))
                {
                    addresses.Add(address);
                }
                else
                {
                    MessageBox.Show("Please enter a valid IPv6 address.", "Invalid IPv6 Address!", MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
                    return;
                }
            }

            if (addresses.Count == 0)
            {
                MessageBox.Show("Please enter at least one valid DNS provider IP address.", "Missing DNS Provider IP Address!", MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
                return;
            }

            if ((btnAddUpdate.Text != "Add") && (listView1.SelectedItems.Count > 0))
            {
                ListViewItem selectedItem = listView1.SelectedItems[0];
                DnsProvider dnsProvider = selectedItem.Tag as DnsProvider;

                dnsProvider.Name = txtDnsProviderName.Text.Trim();
                dnsProvider.Addresses = addresses;
            }
            else
            {
                _dnsProviders.Add(new DnsProvider(txtDnsProviderName.Text.Trim(), addresses));
            }

            RefreshDnsProvidersList();
            ClearForm();
        }

        private void btnDelete_Click(object sender, EventArgs e)
        {
            if (listView1.SelectedItems.Count > 0)
            {
                ListViewItem selectedItem = listView1.SelectedItems[0];
                DnsProvider dnsProvider = selectedItem.Tag as DnsProvider;

                _dnsProviders.Remove(dnsProvider);
                listView1.Items.Remove(selectedItem);
            }

            RefreshDnsProvidersList();
            ClearForm();
        }

        private void btnClear_Click(object sender, EventArgs e)
        {
            ClearForm();
        }

        private void btnRestoreDefaults_Click(object sender, EventArgs e)
        {
            _dnsProviders.Clear();
            _dnsProviders.AddRange(DnsProvider.GetDefaultProviders());

            RefreshDnsProvidersList();
            ClearForm();
        }

        #endregion

        #region properties

        public List<DnsProvider> DnsProviders
        { get { return _dnsProviders; } }

        #endregion
    }
}
