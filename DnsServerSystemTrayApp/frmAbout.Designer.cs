namespace DnsServerSystemTrayApp
{
    partial class frmAbout
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(frmAbout));
            panel1 = new System.Windows.Forms.Panel();
            pictureBox1 = new System.Windows.Forms.PictureBox();
            label2 = new System.Windows.Forms.Label();
            label4 = new System.Windows.Forms.Label();
            lnkTerms = new System.Windows.Forms.LinkLabel();
            btnClose = new System.Windows.Forms.Button();
            label3 = new System.Windows.Forms.Label();
            lnkWebsite = new System.Windows.Forms.LinkLabel();
            label1 = new System.Windows.Forms.Label();
            lnkContactEmail = new System.Windows.Forms.LinkLabel();
            labVersion = new System.Windows.Forms.Label();
            label5 = new System.Windows.Forms.Label();
            panel1.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)pictureBox1).BeginInit();
            SuspendLayout();
            // 
            // panel1
            // 
            panel1.BackColor = System.Drawing.Color.FromArgb(102, 153, 255);
            panel1.Controls.Add(pictureBox1);
            panel1.Dock = System.Windows.Forms.DockStyle.Left;
            panel1.Location = new System.Drawing.Point(0, 0);
            panel1.Margin = new System.Windows.Forms.Padding(4, 3, 4, 3);
            panel1.Name = "panel1";
            panel1.Size = new System.Drawing.Size(58, 301);
            panel1.TabIndex = 21;
            // 
            // pictureBox1
            // 
            pictureBox1.BackColor = System.Drawing.Color.FromArgb(102, 153, 255);
            pictureBox1.Dock = System.Windows.Forms.DockStyle.Bottom;
            pictureBox1.Image = Properties.Resources.logo;
            pictureBox1.Location = new System.Drawing.Point(0, 243);
            pictureBox1.Margin = new System.Windows.Forms.Padding(4, 3, 4, 3);
            pictureBox1.Name = "pictureBox1";
            pictureBox1.Padding = new System.Windows.Forms.Padding(5);
            pictureBox1.Size = new System.Drawing.Size(58, 58);
            pictureBox1.SizeMode = System.Windows.Forms.PictureBoxSizeMode.AutoSize;
            pictureBox1.TabIndex = 12;
            pictureBox1.TabStop = false;
            // 
            // label2
            // 
            label2.AutoSize = true;
            label2.Font = new System.Drawing.Font("Arial", 30F, System.Drawing.FontStyle.Bold);
            label2.ForeColor = System.Drawing.Color.FromArgb(45, 57, 69);
            label2.Location = new System.Drawing.Point(88, 28);
            label2.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            label2.Name = "label2";
            label2.Size = new System.Drawing.Size(456, 46);
            label2.TabIndex = 24;
            label2.Text = "Technitium DNS Server";
            // 
            // label4
            // 
            label4.Anchor = System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left;
            label4.Font = new System.Drawing.Font("Arial", 8F);
            label4.ForeColor = System.Drawing.Color.FromArgb(45, 57, 69);
            label4.Location = new System.Drawing.Point(72, 223);
            label4.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            label4.Name = "label4";
            label4.Size = new System.Drawing.Size(509, 51);
            label4.TabIndex = 33;
            label4.Text = resources.GetString("label4.Text");
            // 
            // lnkTerms
            // 
            lnkTerms.Anchor = System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left;
            lnkTerms.AutoSize = true;
            lnkTerms.Font = new System.Drawing.Font("Arial", 9F);
            lnkTerms.LinkColor = System.Drawing.Color.FromArgb(102, 153, 255);
            lnkTerms.Location = new System.Drawing.Point(72, 273);
            lnkTerms.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            lnkTerms.Name = "lnkTerms";
            lnkTerms.Size = new System.Drawing.Size(116, 15);
            lnkTerms.TabIndex = 32;
            lnkTerms.TabStop = true;
            lnkTerms.Text = "Terms && Conditions";
            lnkTerms.VisitedLinkColor = System.Drawing.Color.White;
            lnkTerms.LinkClicked += lnkTerms_LinkClicked;
            // 
            // btnClose
            // 
            btnClose.Anchor = System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Right;
            btnClose.DialogResult = System.Windows.Forms.DialogResult.Cancel;
            btnClose.Location = new System.Drawing.Point(659, 264);
            btnClose.Margin = new System.Windows.Forms.Padding(4, 3, 4, 3);
            btnClose.Name = "btnClose";
            btnClose.Size = new System.Drawing.Size(88, 27);
            btnClose.TabIndex = 31;
            btnClose.Text = "&Close";
            btnClose.UseVisualStyleBackColor = true;
            // 
            // label3
            // 
            label3.AutoSize = true;
            label3.Font = new System.Drawing.Font("Arial", 10F);
            label3.ForeColor = System.Drawing.Color.FromArgb(45, 57, 69);
            label3.Location = new System.Drawing.Point(555, 166);
            label3.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            label3.Name = "label3";
            label3.Size = new System.Drawing.Size(58, 16);
            label3.TabIndex = 37;
            label3.Text = "Website";
            // 
            // lnkWebsite
            // 
            lnkWebsite.AutoSize = true;
            lnkWebsite.Font = new System.Drawing.Font("Arial", 10F);
            lnkWebsite.LinkColor = System.Drawing.Color.FromArgb(102, 153, 255);
            lnkWebsite.Location = new System.Drawing.Point(555, 185);
            lnkWebsite.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            lnkWebsite.Name = "lnkWebsite";
            lnkWebsite.Size = new System.Drawing.Size(128, 16);
            lnkWebsite.TabIndex = 36;
            lnkWebsite.TabStop = true;
            lnkWebsite.Text = "technitium.com/dns";
            lnkWebsite.VisitedLinkColor = System.Drawing.Color.White;
            lnkWebsite.LinkClicked += lnkWebsite_LinkClicked;
            // 
            // label1
            // 
            label1.AutoSize = true;
            label1.Font = new System.Drawing.Font("Arial", 10F);
            label1.ForeColor = System.Drawing.Color.FromArgb(45, 57, 69);
            label1.Location = new System.Drawing.Point(555, 114);
            label1.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            label1.Name = "label1";
            label1.Size = new System.Drawing.Size(56, 16);
            label1.TabIndex = 35;
            label1.Text = "Contact";
            // 
            // lnkContactEmail
            // 
            lnkContactEmail.AutoSize = true;
            lnkContactEmail.Font = new System.Drawing.Font("Arial", 10F);
            lnkContactEmail.LinkColor = System.Drawing.Color.FromArgb(102, 153, 255);
            lnkContactEmail.Location = new System.Drawing.Point(555, 133);
            lnkContactEmail.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            lnkContactEmail.Name = "lnkContactEmail";
            lnkContactEmail.Size = new System.Drawing.Size(163, 16);
            lnkContactEmail.TabIndex = 34;
            lnkContactEmail.TabStop = true;
            lnkContactEmail.Text = "support@technitium.com";
            lnkContactEmail.VisitedLinkColor = System.Drawing.Color.White;
            lnkContactEmail.LinkClicked += lnkContactEmail_LinkClicked;
            // 
            // labVersion
            // 
            labVersion.AutoSize = true;
            labVersion.Font = new System.Drawing.Font("Arial", 12F);
            labVersion.ForeColor = System.Drawing.Color.FromArgb(45, 57, 69);
            labVersion.Location = new System.Drawing.Point(100, 152);
            labVersion.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            labVersion.Name = "labVersion";
            labVersion.Size = new System.Drawing.Size(102, 18);
            labVersion.TabIndex = 38;
            labVersion.Text = "version x.x.x.x";
            // 
            // label5
            // 
            label5.AutoSize = true;
            label5.Font = new System.Drawing.Font("Arial", 18F, System.Drawing.FontStyle.Bold);
            label5.ForeColor = System.Drawing.Color.FromArgb(45, 57, 69);
            label5.Location = new System.Drawing.Point(98, 119);
            label5.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            label5.Name = "label5";
            label5.Size = new System.Drawing.Size(206, 29);
            label5.TabIndex = 39;
            label5.Text = "System Tray App";
            // 
            // frmAbout
            // 
            AcceptButton = btnClose;
            AutoScaleDimensions = new System.Drawing.SizeF(7F, 15F);
            AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            BackColor = System.Drawing.Color.FromArgb(250, 250, 250);
            CancelButton = btnClose;
            ClientSize = new System.Drawing.Size(761, 301);
            Controls.Add(label5);
            Controls.Add(labVersion);
            Controls.Add(label3);
            Controls.Add(lnkWebsite);
            Controls.Add(label1);
            Controls.Add(lnkContactEmail);
            Controls.Add(label4);
            Controls.Add(lnkTerms);
            Controls.Add(btnClose);
            Controls.Add(label2);
            Controls.Add(panel1);
            FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedDialog;
            Icon = (System.Drawing.Icon)resources.GetObject("$this.Icon");
            Margin = new System.Windows.Forms.Padding(4, 3, 4, 3);
            MaximizeBox = false;
            MinimizeBox = false;
            Name = "frmAbout";
            StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            Text = "About Technitium DNS Server";
            panel1.ResumeLayout(false);
            panel1.PerformLayout();
            ((System.ComponentModel.ISupportInitialize)pictureBox1).EndInit();
            ResumeLayout(false);
            PerformLayout();
        }

        #endregion
        private System.Windows.Forms.Panel panel1;
        private System.Windows.Forms.PictureBox pictureBox1;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.Label label4;
        private System.Windows.Forms.LinkLabel lnkTerms;
        private System.Windows.Forms.Button btnClose;
        private System.Windows.Forms.Label label3;
        private System.Windows.Forms.LinkLabel lnkWebsite;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.LinkLabel lnkContactEmail;
        private System.Windows.Forms.Label labVersion;
        private System.Windows.Forms.Label label5;
    }
}