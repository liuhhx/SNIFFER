
namespace WinFormsSniffer
{
    partial class Form1
    {
        /// <summary>
        ///  Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        ///  Clean up any resources being used.
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
        ///  Required method for Designer support - do not modify
        ///  the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.overviews = new System.Windows.Forms.ListView();
            this.label1 = new System.Windows.Forms.Label();
            this.sniffer_button = new System.Windows.Forms.Button();
            this.columnHeader1 = new System.Windows.Forms.ColumnHeader();
            this.columnHeader2 = new System.Windows.Forms.ColumnHeader();
            this.columnHeader3 = new System.Windows.Forms.ColumnHeader();
            this.columnHeader4 = new System.Windows.Forms.ColumnHeader();
            this.columnHeader5 = new System.Windows.Forms.ColumnHeader();
            this.columnHeader6 = new System.Windows.Forms.ColumnHeader();
            this.columnHeader7 = new System.Windows.Forms.ColumnHeader();
            this.Contents = new System.Windows.Forms.RichTextBox();
            this.overview_tcp = new System.Windows.Forms.ListView();
            this.SuspendLayout();
            // 
            // overviews
            // 
            this.overviews.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            this.columnHeader1,
            this.columnHeader2,
            this.columnHeader3,
            this.columnHeader4,
            this.columnHeader5,
            this.columnHeader6,
            this.columnHeader7});
            this.overviews.HideSelection = false;
            this.overviews.Location = new System.Drawing.Point(39, 57);
            this.overviews.Name = "overviews";
            this.overviews.Size = new System.Drawing.Size(692, 380);
            this.overviews.TabIndex = 0;
            this.overviews.UseCompatibleStateImageBehavior = false;
            this.overviews.View = System.Windows.Forms.View.Details;
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(39, 34);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(39, 20);
            this.label1.TabIndex = 1;
            this.label1.Text = "报文";
            // 
            // sniffer_button
            // 
            this.sniffer_button.Location = new System.Drawing.Point(637, 25);
            this.sniffer_button.Name = "sniffer_button";
            this.sniffer_button.Size = new System.Drawing.Size(94, 29);
            this.sniffer_button.TabIndex = 2;
            this.sniffer_button.Text = "嗅探";
            this.sniffer_button.UseVisualStyleBackColor = true;
            this.sniffer_button.Click += new System.EventHandler(this.sniffer_button_Click);
            // 
            // columnHeader1
            // 
            this.columnHeader1.Tag = "源IP";
            // 
            // columnHeader2
            // 
            this.columnHeader2.Tag = "目的IP";
            // 
            // columnHeader3
            // 
            this.columnHeader3.Tag = "源端口";
            // 
            // columnHeader4
            // 
            this.columnHeader4.Tag = "目的端口";
            // 
            // columnHeader5
            // 
            this.columnHeader5.Tag = "协议";
            // 
            // columnHeader6
            // 
            this.columnHeader6.Tag = "IP包字节数";
            // 
            // columnHeader7
            // 
            this.columnHeader7.Tag = "总字节数";
            // 
            // Contents
            // 
            this.Contents.Location = new System.Drawing.Point(39, 452);
            this.Contents.Name = "Contents";
            this.Contents.Size = new System.Drawing.Size(692, 186);
            this.Contents.TabIndex = 3;
            this.Contents.Text = "";
            // 
            // overview_tcp
            // 
            this.overview_tcp.HideSelection = false;
            this.overview_tcp.Location = new System.Drawing.Point(737, 57);
            this.overview_tcp.Name = "overview_tcp";
            this.overview_tcp.Size = new System.Drawing.Size(364, 380);
            this.overview_tcp.TabIndex = 4;
            this.overview_tcp.UseCompatibleStateImageBehavior = false;
            // 
            // Form1
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(9F, 20F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(1123, 706);
            this.Controls.Add(this.overview_tcp);
            this.Controls.Add(this.Contents);
            this.Controls.Add(this.sniffer_button);
            this.Controls.Add(this.label1);
            this.Controls.Add(this.overviews);
            this.Name = "Form1";
            this.Text = "Sniffer";
            this.Load += new System.EventHandler(this.Form1_Load);
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.ListView overviews;
        private System.Windows.Forms.ColumnHeader columnHeader1;
        private System.Windows.Forms.ColumnHeader columnHeader2;
        private System.Windows.Forms.ColumnHeader columnHeader3;
        private System.Windows.Forms.ColumnHeader columnHeader4;
        private System.Windows.Forms.ColumnHeader columnHeader5;
        private System.Windows.Forms.ColumnHeader columnHeader6;
        private System.Windows.Forms.ColumnHeader columnHeader7;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.Button sniffer_button;
        private System.Windows.Forms.RichTextBox Contents;
        private System.Windows.Forms.ListView overview_tcp;
    }
}

