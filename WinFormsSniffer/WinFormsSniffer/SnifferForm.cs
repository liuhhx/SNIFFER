using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.DirectoryServices.ActiveDirectory;
using System.Drawing;
using System.IO;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using System.Windows.Forms.VisualStyles;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;

namespace WinFormsSniffer
{
    public partial class SnifferForm : Form
    {
        List<LibPcapLiveDevice> _interfaceList = new List<LibPcapLiveDevice>();
        int selectedIntIndex;
        LibPcapLiveDevice wifi_device;
        CaptureFileWriterDevice captureFileWriter;
        Dictionary<int, Packet> capturedPackets_list = new Dictionary<int, Packet>();
        int packetNumber = 1;
        string time_str = "", sourceIP = "", destinationIP = "", protocol_type = "", length = "";

        private bool StartSniffing = false;

        Thread sniffing;

        /// <summary>
        /// 包信息
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void listView1_ItemSelectionChanged(object sender, ListViewItemSelectionChangedEventArgs e)
        {
            string protocol = e.Item.SubItems[4].Text; // todo 这是啥
            int key = Int32.Parse(e.Item.SubItems[0].Text);
            Packet packet;
            bool getPacket = capturedPackets_list.TryGetValue(key, out packet);

            switch (protocol)
            {
                case "TCP":
                    if (getPacket)
                    {
                        var tcpPacket = (TcpPacket) packet.Extract(typeof(TcpPacket));
                        if (tcpPacket != null)
                        {
                            int srcPort = tcpPacket.SourcePort;
                            int desPort = tcpPacket.DestinationPort;
                            var checksum = tcpPacket.Checksum;

                            textBox2.Text = "";
                            textBox2.Text = "Packet number:" + key +
                                            "协议:TCP" +
                                            "\r\n源地址：" + srcPort +
                                            "\r\n目的地址：" + desPort +
                                            "\r\nTCP头部大小：" + tcpPacket.DataOffset +
                                            "\r\n窗口大小：" + tcpPacket.WindowSize +
                                            "\r\nCheckSum:" + checksum +
                                            (tcpPacket.ValidChecksum ? ",valid" : "invalid") +
                                            "\r\nTCP CheckSum:" + (tcpPacket.ValidChecksum ? ",valid" : ",invalid") +
                                            "\r\nSequence number:" + tcpPacket.SequenceNumber +
                                            "\r\nAcknowledgement number:" + tcpPacket.AcknowledgmentNumber +
                                            (tcpPacket.Ack ? ",valid" : ",invalid") +
                                            "\r\nUrgent pointer: " + (tcpPacket.Urg ? "valid" : "invalid") +
                                            "\r\nACK flag: " +
                                            (tcpPacket.Ack
                                                ? "1"
                                                : "0") + // indicates if the AcknowledgmentNumber is valid
                                            "\r\nPSH flag: " +
                                            (tcpPacket.Psh
                                                ? "1"
                                                : "0"
                                            ) + // push 1 = the receiver should pass the data to the app immidiatly, don't buffer it
                                            "\r\nRST flag: " +
                                            (tcpPacket.Rst ? "1" : "0") + // reset 1 is to abort existing connection
                                            // SYN indicates the sequence numbers should be synchronized between the sender and receiver to initiate a connection
                                            "\r\nSYN flag: " + (tcpPacket.Syn ? "1" : "0") +
                                            // closing the connection with a deal, host_A sends FIN to host_B, B responds with ACK
                                            // FIN flag indicates the sender is finished sending
                                            "\r\nFIN flag: " + (tcpPacket.Fin ? "1" : "0") +
                                            "\r\nECN flag: " + (tcpPacket.ECN ? "1" : "0") +
                                            "\r\nCWR flag: " + (tcpPacket.CWR ? "1" : "0") +
                                            "\r\nNS flag: " + (tcpPacket.NS ? "1" : "0");
                        }
                    }

                    break;
                case "UDP":
                    if (getPacket)
                    {
                        var udpPacket = (UdpPacket) packet.Extract(typeof(UdpPacket));
                        if (udpPacket != null)
                        {
                            int srcPort = udpPacket.SourcePort;
                            int dstPort = udpPacket.DestinationPort;
                            var checksum = udpPacket.Checksum;

                            textBox2.Text = "";
                            textBox2.Text = "Packet number: " + key +
                                            " Type: UDP" +
                                            "\r\nSource port:" + srcPort +
                                            "\r\nDestination port: " + dstPort +
                                            "\r\nChecksum:" + checksum.ToString() + " valid: " +
                                            udpPacket.ValidChecksum +
                                            "\r\nValid UDP checksum: " + udpPacket.ValidUDPChecksum;
                        }
                    }

                    break;
                case "ARP":
                    if (getPacket)
                    {
                        var arpPacket = (ARPPacket) packet.Extract(typeof(ARPPacket));
                        if (arpPacket != null)
                        {
                            System.Net.IPAddress senderAddress = arpPacket.SenderProtocolAddress;
                            System.Net.IPAddress targerAddress = arpPacket.TargetProtocolAddress;
                            System.Net.NetworkInformation.PhysicalAddress senderHardwareAddress =
                                arpPacket.SenderHardwareAddress;
                            System.Net.NetworkInformation.PhysicalAddress targerHardwareAddress =
                                arpPacket.TargetHardwareAddress;

                            textBox2.Text = "";
                            textBox2.Text = "Packet number: " + key +
                                            " Type: ARP" +
                                            "\r\nHardware address length:" + arpPacket.HardwareAddressLength +
                                            "\r\nProtocol address length: " + arpPacket.ProtocolAddressLength +
                                            "\r\nOperation: " +
                                            arpPacket.Operation
                                                .ToString() + // ARP request or ARP reply ARP_OP_REQ_CODE, ARP_OP_REP_CODE
                                            "\r\nSender protocol address: " + senderAddress +
                                            "\r\nTarget protocol address: " + targerAddress +
                                            "\r\nSender hardware address: " + senderHardwareAddress +
                                            "\r\nTarget hardware address: " + targerHardwareAddress;
                        }
                    }

                    break;
                case "ICMP":
                    if (getPacket)
                    {
                        var icmpPacket = (ICMPv4Packet) packet.Extract(typeof(ICMPv4Packet));
                        if (icmpPacket != null)
                        {
                            textBox2.Text = "";
                            textBox2.Text = "Packet number: " + key +
                                            " Type: ICMP v4" +
                                            "\r\nType Code: 0x" + icmpPacket.TypeCode.ToString("x") +
                                            "\r\nChecksum: " + icmpPacket.Checksum.ToString("x") +
                                            "\r\nID: 0x" + icmpPacket.ID.ToString("x") +
                                            "\r\nSequence number: " + icmpPacket.Sequence.ToString("x");
                        }
                    }

                    break;
                case "IGMP":
                    if (getPacket)
                    {
                        var igmpPacket = (IGMPv2Packet) packet.Extract(typeof(IGMPv2Packet));
                        if (igmpPacket != null)
                        {
                            textBox2.Text = "";
                            textBox2.Text = "Packet number: " + key +
                                            " Type: IGMP v2" +
                                            "\r\nType: " + igmpPacket.Type +
                                            "\r\nGroup address: " + igmpPacket.GroupAddress +
                                            "\r\nMax response time" + igmpPacket.MaxResponseTime;
                        }
                    }

                    break;
                default:
                    textBox2.Text = "";
                    break;
            }
        }

        public SnifferForm(List<LibPcapLiveDevice> interfaces, int selectedIndex)
        {
            InitializeComponent();
            this._interfaceList = interfaces;
            this.selectedIntIndex = selectedIndex;
            wifi_device = _interfaceList[selectedIntIndex];
        }

        /// <summary>
        /// 开始监听
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void Start_Click(object sender, EventArgs e)
        {
            if (StartSniffing == false)
            {
                File.Delete(Environment.CurrentDirectory + "sniffer.pcap");
                wifi_device.OnPacketArrival += Device_OnPacketArrival;
                sniffing = new Thread(new ThreadStart(Sniffing_Process));
                sniffing.Start();
                Start.Enabled = false;
                Close.Enabled = true;
                textBox1.Enabled = false;

            }
            else if (StartSniffing)
            {
                if (MessageBox.Show("您的数据包已被捕获到文件中，开始新的捕获将覆盖现有的捕获。", "确认", MessageBoxButtons.OK,
                    MessageBoxIcon.Warning) == DialogResult.OK)
                {
                    // 点击了确定
                    File.Delete(Environment.CurrentDirectory + "sniffer.pcap");
                    listView1.Items.Clear();
                    capturedPackets_list.Clear();
                    packetNumber = 1;
                    textBox2.Text = "";
                    wifi_device.OnPacketArrival += Device_OnPacketArrival;
                    sniffing = new Thread(Sniffing_Process);
                    sniffing.Start();
                    Start.Enabled = false;
                    Close.Enabled = true;
                    textBox1.Enabled = false;
                }
            }

            StartSniffing = true;
        }

        public void Device_OnPacketArrival(object sender, SharpPcap.CaptureEventArgs e)
        {
            // 写进文件
            captureFileWriter.Write(e.Packet);
            // 开始提取属性信息
            DateTime time = e.Packet.Timeval.Date;
            time_str = (time.Hour + 1) + ":" + time.Minute + ":" + time.Second + ":" + time.Millisecond;
            length = e.Packet.Data.Length.ToString();

            var packet = PacketDotNet.Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
            // 添加到list

            capturedPackets_list.Add(packetNumber, packet);

            var ipPacket = (IpPacket) packet.Extract(typeof(IpPacket));

            if (ipPacket != null)
            {
                System.Net.IPAddress srcIp = ipPacket.SourceAddress;
                System.Net.IPAddress desIp = ipPacket.DestinationAddress;
                protocol_type = ipPacket.Protocol.ToString();
                sourceIP = srcIp.ToString();
                destinationIP = desIp.ToString();

                var protocolPacket = ipPacket.PayloadPacket;

                ListViewItem item = new ListViewItem(packetNumber.ToString());
                item.SubItems.Add(time_str);
                item.SubItems.Add(sourceIP);
                item.SubItems.Add(destinationIP);
                item.SubItems.Add(protocol_type);
                item.SubItems.Add(length);

                void Action() => listView1.Items.Add(item);
                listView1.Invoke((Action) Action);
                ++packetNumber;
            }
        }

        private void Sniffing_Process()
        {
            // 打开设备准备嗅探
            int readTimeoutMillisecondes = 1000;
            wifi_device.Open(DeviceMode.Promiscuous, readTimeoutMillisecondes);

            // 开始嗅探
            if (wifi_device.Opened)
            {
                if (textBox1.Text != "") wifi_device.Filter = textBox1.Text;
                captureFileWriter =
                    new CaptureFileWriterDevice(wifi_device, Environment.CurrentDirectory + "sniffer.pcap");
                wifi_device.Capture();
            }
        }
    }
}