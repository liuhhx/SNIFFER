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
            string protocol = e.Item.SubItems[4].Text; // 第五列内容值 也就是协议值
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
                            textBox2.Text = "序号:" + key +
                                            "\r\n协议:TCP" +
                                            "\r\n源地址：" + srcPort +
                                            "\r\n目的地址：" + desPort +
                                            "\r\nTCP头部大小：" + tcpPacket.DataOffset +
                                            "\r\n窗口大小：" + tcpPacket.WindowSize +
                                            "\r\n校验和:" + checksum +
                                            (tcpPacket.ValidChecksum ? ",valid" : "invalid") +
                                            "\r\nTCP检验和:" + (tcpPacket.ValidChecksum ? ",valid" : ",invalid") +
                                            "\r\n序列号:" + tcpPacket.SequenceNumber +
                                            "\r\n确认号:" + tcpPacket.AcknowledgmentNumber +
                                            (tcpPacket.Ack ? ",valid" : ",invalid") +
                                            "\r\nUrgent pointer: " + (tcpPacket.Urg ? "valid" : "invalid") +
                                            "\r\nACK flag: " +
                                            (tcpPacket.Ack
                                                ? "1"
                                                : "0") + // 确认号有效
                                            "\r\nPSH flag: " +
                                            (tcpPacket.Psh
                                                ? "1"
                                                : "0"
                                            ) + // 1 接收者会立即将数据传递给app,而不会缓冲
                                            "\r\nRST flag: " +
                                            (tcpPacket.Rst ? "1" : "0") + // 1 终止现有连接
                                            // SYN表示发送方和接收方以同步序号发起连接
                                            "\r\nSYN flag: " + (tcpPacket.Syn ? "1" : "0") +
                                            // 关闭连接，A向B发送FIN,B回一个ACK
                                            // FIN flag 表示发送方以完成发送
                                            "\r\nFIN flag: " + (tcpPacket.Fin ? "1" : "0") +
                                            "\r\nECN flag: " + (tcpPacket.ECN ? "1" : "0") +
                                            "\r\nCWR flag: " + (tcpPacket.CWR ? "1" : "0") +
                                            "\r\nNS flag: " + (tcpPacket.NS ? "1" : "0");
                        }
                    }
                    break;
                case "UDP":
                    //todo 为什么UDP就会报An item with the same key has already been added. 这个错误呢？
                    if (getPacket)
                    {
                        var udpPacket = (UdpPacket) packet.Extract(typeof(UdpPacket));
                        if (udpPacket != null)
                        {
                            int srcPort = udpPacket.SourcePort;
                            int dstPort = udpPacket.DestinationPort;
                            var checksum = udpPacket.Checksum;

                            textBox2.Text = "";
                            textBox2.Text = "包序号: " + key +
                                            "\r\nType: UDP" +
                                            "\r\n源地址:" + srcPort +
                                            "\r\n目的地址: " + dstPort +
                                            "\r\n校验和:" + checksum.ToString() + " valid: " +
                                            udpPacket.ValidChecksum +
                                            "\r\n有效 UDP 校验和: " + udpPacket.ValidUDPChecksum;
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
                            System.Net.IPAddress targetAddress = arpPacket.TargetProtocolAddress;
                            System.Net.NetworkInformation.PhysicalAddress senderHardwareAddress =
                                arpPacket.SenderHardwareAddress;
                            System.Net.NetworkInformation.PhysicalAddress targetHardwareAddress =
                                arpPacket.TargetHardwareAddress;

                            textBox2.Text = "";
                            textBox2.Text = "序号: " + key +
                                            "\r\nType: ARP" +
                                            "\r\n硬件地址长度:" + arpPacket.HardwareAddressLength +
                                            "\r\n协议地址长度: " + arpPacket.ProtocolAddressLength +
                                            "\r\n操作: " +
                                            arpPacket.Operation
                                                .ToString() + // ARP request or ARP reply ARP_OP_REQ_CODE, ARP_OP_REP_CODE
                                            "\r\n发送方协议地址: " + senderAddress +
                                            "\r\n目标协议地址: " + targetAddress +
                                            "\r\n发送方硬件地址: " + senderHardwareAddress +
                                            "\r\n目标硬件地址: " + targetHardwareAddress;
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
                            textBox2.Text = "序号: " + key +
                                            "\r\nType: ICMP v4" +
                                            "\r\nType Code: 0x" + icmpPacket.TypeCode.ToString("x") +
                                            "\r\n检验和: " + icmpPacket.Checksum.ToString("x") +
                                            "\r\nID: 0x" + icmpPacket.ID.ToString("x") +
                                            "\r\n序列号: " + icmpPacket.Sequence.ToString("x");
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
                            textBox2.Text = "序号: " + key +
                                            "\r\nType: IGMP v2" +
                                            "\r\nType: " + igmpPacket.Type +
                                            "\r\n组地址: " + igmpPacket.GroupAddress +
                                            "\r\n最大响应时间" + igmpPacket.MaxResponseTime;
                        }
                    }
                    break;
                default:
                    textBox2.Text = "";
                    break;
            }
        }

        private void Close_Click(object sender, EventArgs e)
        {
            sniffing.Interrupt(); //todo 醒目 abort 在 dotnet core中好像不行 改用interrupt
            wifi_device.StopCapture();
            wifi_device.Close();
            captureFileWriter.Close();
            Start.Enabled = true;
            textBox1.Enabled = true;
            Close.Enabled = false;
        }
        /// <summary>
        /// 选择网卡
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void SelectNetCard_SelectedIndexChanged(object sender, EventArgs e)
        {
            if (SelectNetCard.SelectedIndex >= 0 && SelectNetCard.SelectedIndex < _interfaceList.Count)
            {
                //SnifferForm sniffer = new SnifferForm(interfaceList, comboBox1.SelectedIndex);
                selectedIntIndex = SelectNetCard.SelectedIndex;
                wifi_device = _interfaceList[selectedIntIndex];

            }
        }

        private void SnifferForm_Load(object sender, EventArgs e)
        {
            Close.Enabled = false;
            LibPcapLiveDeviceList devices = LibPcapLiveDeviceList.Instance; // 

            foreach (var device in devices)
            {
                if (!device.Interface.Addresses.Exists(a => a != null && a.Addr != null && a.Addr.ipAddress != null)) continue;
                var devInterface = device.Interface;
                var friendlyName = devInterface.FriendlyName;
                var description = devInterface.Description;

                _interfaceList.Add(device);
                SelectNetCard.Items.Add(friendlyName);
            }
        }

        public SnifferForm()
        {
            InitializeComponent();
            /*this._interfaceList = interfaces;
            this.selectedIntIndex = selectedIndex;
            wifi_device = _interfaceList[selectedIntIndex];*/
        }

        /// <summary>
        /// 开始监听
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void Start_Click(object sender, EventArgs e)
        {
            if (SelectNetCard.SelectedIndex >= 0 && SelectNetCard.SelectedIndex < _interfaceList.Count)
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
            else
            {
                MessageBox.Show("请选择网卡","提示");
            }
            
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
            // 这里会报错，感觉是线程问题？
            // 2022/04/06 21:39:03 没啥办法了 加判断吧
            if (!capturedPackets_list.ContainsKey(packetNumber))
            {
                capturedPackets_list.Add(packetNumber, packet);
            }
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
                // todo 以上这5项为什么不显示？
                // listview设置问题
                /*void Action() => listView1.Items.Add(item);
                listView1.Invoke((Action) Action);*/
                Action action = () => listView1.Items.Add(item);
                listView1.Invoke(action);
                ++packetNumber;
            }
        }

        private void Sniffing_Process()
        {
            // 打开设备准备嗅探
            int readTimeoutMillisecondes = 3000;
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
