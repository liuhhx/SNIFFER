using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace WinFormsSniffer
{
    public partial class Form1 : Form
    {
        public Socket Socket = null;
        public int count = 0;

        public Form1()
        {
            InitializeComponent();
        }

        private void sniffer_button_Click(object sender, EventArgs e)
        {
            try
            {
                byte[] inBytes = BitConverter.GetBytes(1);
                byte[] outBytes = BitConverter.GetBytes(0);
                // 定义一个套接字
                Socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw,protocolType:ProtocolType.IP);

                IPHostEntry ipHost = Dns.GetHostEntry(Dns.GetHostName());
                if (ipHost!=null)
                {
                    Socket.Bind(new IPEndPoint(ipHost.AddressList[3],0));
                }

                Socket.IOControl(IOControlCode.ReceiveAll, inBytes, outBytes);
                sniffer_button.Enabled = false;
                Thread thread = new Thread(CatchPacket);
                thread.IsBackground = true;
                thread.Start(Socket);
            }
            catch (Exception exception)
            {
                Console.WriteLine(exception);
                throw;
            }
        }

        /// <summary>
        /// 抓包
        /// </summary>
        /// <param name="s"></param>
        public void CatchPacket(Object s)
        {
            Socket socket = s as Socket; // 参数转换
            byte[] buffer = new byte[2400]; // 接收数据的缓冲区
            while (true)
            {
                if (count > 80000) break;
                if (socket != null)
                {
                    int j = socket.Receive(buffer); // 接收数据
                    if (j>0) //若接收到数据包
                    {
                        IpHeader ipHeader = new IpHeader(buf:buffer,len:j);
                        ListViewItem lv = new ListViewItem(); //定义一个视图项
                        count += j; // count用于统计接收的总字节数

                        lv.Text = ipHeader.SrcAddress.ToString(); // 往视图项添加源IP
                        lv.SubItems.Add(ipHeader.DesAddress.ToString());// 往视图项添加目的IP
                        if (ipHeader.Protocol==6)
                        {
                            byte[] tcp = new byte[ipHeader.Length - ipHeader.IpLength];
                            Array.Copy(buffer, ipHeader.IpLength, tcp, 0, j - ipHeader.IpLength);
                            TcpHeader tcpHeader = new TcpHeader(tcp, j);//解析TCP报文
                            lv.SubItems.Add(tcpHeader.SourcePort.ToString());
                            lv.SubItems.Add(tcpHeader.DestinationPort.ToString());
                            lv.SubItems.Add("TCP");

                            ListViewItem tcpListViewItem = new ListViewItem();
                            tcpListViewItem.Text = tcpHeader.SourcePort.ToString();
                            tcpListViewItem.SubItems.Add(tcpHeader.DestinationPort.ToString());
                            tcpListViewItem.SubItems.Add(tcpHeader.Seq.ToString());
                            tcpListViewItem.SubItems.Add(tcpHeader.Ack.ToString());
                            tcpListViewItem.SubItems.Add(tcpHeader.DataOffset.ToString());
                            tcpListViewItem.SubItems.Add(tcpHeader.Win.ToString());
                            overview_tcp.Items.Add(tcpListViewItem);

                            string str = Encoding.UTF8.GetString(buffer, 40, j - 40);
                            Contents.AppendText("\r\n"+str);
                        }
                        else if (ipHeader.Protocol == 17)
                        {
                            byte[] udp = new byte[ipHeader.Length-ipHeader.IpLength];
                            Array.Copy(buffer, ipHeader.IpLength, udp, 0, j - ipHeader.IpLength);
                            UdpHeader udpHeader = new UdpHeader(udp,j); //解析UDP报文
                            lv.SubItems.Add(udpHeader.SourcePort.ToString());
                            lv.SubItems.Add(udpHeader.DestinationPort.ToString());
                            lv.SubItems.Add("UDP");
                        }
                        else
                        {// 其他协议
                            lv.SubItems.Add(" ");
                            lv.SubItems.Add(" ");
                            lv.SubItems.Add("Others");
                        }
                        lv.SubItems.Add((ipHeader.Length).ToString());
                        lv.SubItems.Add(count.ToString());
                        this.overviews.Items.Add(lv);

                    }
                }
            }
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            Control.CheckForIllegalCrossThreadCalls = false;
            this.overviews.Columns[0].Width = 130;
            this.overviews.Columns[1].Width = 130;
            this.overviews.Columns[2].Width = 90;
            this.overviews.Columns[3].Width = 90;
            this.overviews.Columns[4].Width = 90;
            this.overviews.Columns[5].Width = 90;
        }
    }
}
