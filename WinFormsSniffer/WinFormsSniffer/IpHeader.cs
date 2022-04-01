using System;
using System.Collections.Generic;
using System.Net;
using System.Text;

namespace WinFormsSniffer
{
    public class IpHeader
    {
        public int Version;
        public int IpLength;
        public byte Tos;
        public UInt32 Length;
        public int Identify;
        public int FlagNFrag;
        public byte Ttl;
        public byte Protocol;
        public int CheckSum;
        public IPAddress SrcAddress;
        public IPAddress DesAddress;

        /// <summary>
        /// 构造函数
        /// </summary>
        /// <param name="buf">表示接收到的IP数据包</param>
        /// <param name="len">接收到的字节数</param>
        public IpHeader(byte[] buf, int len)
        {
            if (len>20) // IP报文头部最小为20字节
            {
                Version = (buf[0] & 0xF0) >> 4; //buf[0]前四位表示版本号
                IpLength = ((int)(buf[0] & 0x0F)) * 4; //后四位表示IP头长度
                Tos = buf[1]; //头部服务
                Length = ((UInt32) buf[2] << 8) + (UInt32) buf[3]; //IP报文长度
                Identify = ((int) buf[4] << 8) + (int) buf[5];
                FlagNFrag = ((int) buf[6] << 8) + (int) buf[7];
                Ttl = buf[8];
                Protocol = buf[9];
                CheckSum = (int) buf[10] + (int) buf[11];
                byte[] addr = new byte[4];
                for (int i = 0; i < 4; i++)
                    addr[i] = buf[12 + i];
                SrcAddress = new IPAddress(addr);
                addr = new byte[4];
                for (int i = 0; i < 4; i++)
                    addr[i] = buf[16 + i];
                DesAddress = new IPAddress(addr);
            }
        }
    }

}
