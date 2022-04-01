using System;
using System.Collections.Generic;
using System.Text;

namespace WinFormsSniffer
{
    public class UdpHeader
    {
        public UInt32 SourcePort;//源端口
        public UInt32 DestinationPort;//目的端口
        public UInt32 UdpLength;//Udp报文长度
        public UInt32 CheckSum;//Udp报文校验码

        public UdpHeader(byte[] buf, int count)
        {
            SourcePort = (UInt32)(buf[0] << 8) + buf[1];
            DestinationPort = (UInt32)(buf[2] << 8) + buf[3];
            UdpLength = (UInt32)(buf[4] << 8) + buf[5];
            CheckSum = (UInt32)(buf[6] << 8) + buf[7];
        }
    }
}
