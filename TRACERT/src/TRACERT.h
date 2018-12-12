#ifndef _ITRACERT_H_//防止重复包含头文件
#define _ITRACERT_H_

//IP数据报首部
typedef struct
{
 unsigned char hdr_len :4;  // 首部长度
 unsigned char version :4;  // 版本号
 unsigned char tos;   // 服务类型
 unsigned short total_len;  // 总长度
 unsigned short identifier;  // 标识
 unsigned short frag_and_flags; //标志和偏移 
 unsigned char ttl;   // 生存时间
 unsigned char protocol;  // 协议
 unsigned short checksum;  // 首部校验和
 unsigned long sourceIP;  // 源IP
 unsigned long destIP;   // 目的IP
} IP_HEADER;

LPCSTR ip ;

//ICMP数据首部
typedef struct
{
 BYTE type;  //8位类型
 BYTE code;  //8位代码
 USHORT cksum;  //16位校验和
 USHORT id;   //16位标识符
 USHORT seq;  //16位序列号
} ICMP_HEADER;

//解码结果
typedef struct
{
 USHORT usSeqNo;   //包序列号
 DWORD dwRoundTripTime; //往返时间
 DWORD startTimeStamp;	//起始时间
 in_addr dwIPaddr,hostinfo;  //对端IP地址,本机IP
 DWORD rtt;   		//往返时间

} DECODE_RESULT;

//ICMP类型字段
const BYTE ICMP_ECHO_REQUEST = 8; //请求回显
const BYTE ICMP_ECHO_REPLY  = 0; //回显应答
const BYTE ICMP_TIMEOUT   = 11; //传输超时
const DWORD DEF_ICMP_TIMEOUT = 3000; //默认超时时间，单位ms
const int DEF_ICMP_DATA_SIZE = 32; //默认ICMP数据部分长度
const int MAX_ICMP_PACKET_SIZE = 1024; //最大ICMP数据报的大小
const int DEF_MAX_HOP = 20;    //最大跳站数

const int SEND_ICMP_TIMES = 4;		//发送icmp报的次数，用于统计均值和方差

USHORT GenerateChecksum(USHORT* pBuf, int iSize);
BOOL DecodeIcmpResponse(char* pBuf, int iPacketSize, DECODE_RESULT& stDecodeResult);
// int calculateTheAvgAndAtd

#endif // _ITRACERT_H_ 
