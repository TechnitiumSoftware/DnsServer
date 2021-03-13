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

using System.Diagnostics;
using System.Windows.Forms;

namespace DnsServerSystemTrayApp
{
    public partial class frmAbout : Form
    {
        public frmAbout()
        {
            InitializeComponent();

            labVersion.Text = "version " + Application.ProductVersion;
        }

        private void lnkContactEmail_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
        {
            ProcessStartInfo processInfo = new ProcessStartInfo("mailto:" + lnkContactEmail.Text);

            processInfo.UseShellExecute = true;
            processInfo.Verb = "open";

            Process.Start(processInfo);
        }

        private void lnkWebsite_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
        {
            ProcessStartInfo processInfo = new ProcessStartInfo(@"https://" + lnkWebsite.Text);

            processInfo.UseShellExecute = true;
            processInfo.Verb = "open";

            Process.Start(processInfo);
        }

        private void lnkTerms_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
        {
            ProcessStartInfo processInfo = new ProcessStartInfo(@"https://go.technitium.com/?id=24");

            processInfo.UseShellExecute = true;
            processInfo.Verb = "open";

            Process.Start(processInfo);
        }
    }
}
