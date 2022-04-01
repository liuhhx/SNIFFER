using System;
using System.Collections.Generic;
using System.Text;

namespace WinFormsSniffer
{
    public class TcpHeader
    {
        public UInt32 SourcePort;//16位源端口
        public UInt32 DestinationPort;//16位目的端口
        public UInt32 Seq; //32位序号
        public UInt32 Ack; //32位确认号
        public byte DataOffset;//4位数据偏移
        public byte Reserve;//6位保留
        public byte Flag;//6位标志位；
        public UInt32 Win;//16bit windows
        public UInt32 CheckSum;//16bit check sum
        public UInt32 Point;//urgent point

        public TcpHeader(byte[] buf, int len)
        {
            SourcePort = ((UInt32)buf[0] << 8) + (UInt32)buf[1];//源端口
            DestinationPort = ((UInt32)buf[2] << 8) + (UInt32)buf[3];//目的端口
            Seq = ((UInt32)buf[7] << 24) + ((UInt32)buf[6] << 16) + ((UInt32)buf[5] << 8) + ((UInt32)buf[4]);
            Ack = ((UInt32)buf[11] << 24) + ((UInt32)buf[10] << 16) + ((UInt32)buf[9] << 8) + ((UInt32)buf[8]);
            DataOffset = (byte)((buf[12] & 0xF0) >> 2);
            Reserve = (byte)(buf[12] & 0x0F + buf[13] & 0xC0);
            Flag = (byte)(buf[13] & 0x3F);
            Win = ((UInt32)buf[14] << 8) + buf[15];
            CheckSum = ((UInt32)buf[17] << 8) + buf[16];
            Point = ((UInt32)buf[19] << 8) + buf[18];
        }
    }
}
