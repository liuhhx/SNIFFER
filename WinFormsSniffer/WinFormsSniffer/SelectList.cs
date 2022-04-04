using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Text;
using SharpPcap.LibPcap;
using System.Windows.Forms;

namespace WinFormsSniffer
{
    public partial class SelectList : Form
    {
        readonly List<LibPcapLiveDevice> interfaceList = new List<LibPcapLiveDevice>();
        public SelectList()
        {
            InitializeComponent();
        }

        private void SelectList_Load(object sender, EventArgs e)
        {
            LibPcapLiveDeviceList devices = LibPcapLiveDeviceList.Instance; // 

            foreach (var device in devices)
            {
                if (!device.Interface.Addresses.Exists(a => a != null && a.Addr != null && a.Addr.ipAddress != null)) continue;
                var devInterface = device.Interface;
                var friendlyName = devInterface.FriendlyName;
                var description = devInterface.Description;

                interfaceList.Add(device);
                comboBox1.Items.Add(friendlyName);
            }
        }

        private void button2_Click(object sender, EventArgs e)
        {
            Close();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            if (comboBox1.SelectedIndex >= 0 && comboBox1.SelectedIndex < interfaceList.Count)
            {
                SnifferForm sniffer = new SnifferForm(interfaceList, comboBox1.SelectedIndex);
                Hide();
                sniffer.Show();
            }
        }
    }
}
