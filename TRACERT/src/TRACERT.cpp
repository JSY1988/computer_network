//============================================================================
// Name        : TRACERT.cpp
// Author      : shawn_zhu
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C++, Ansi-style
//============================================================================

// TraceRoute.cpp : Defines the entry point for the console application.




#include "stdafx.h"
#include <iostream>
#include <iomanip>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <math.h>
#include <stdio.h>

#include "TRACERT.h"

#pragma comment(lib,"ws2_32")

using namespace std;

int main(int argc, char* argv[])
{

	 //判断命令行参数是否正确输入ip或者网址
	if (argc != 2)
	{
		cerr << "please enter true arg"<<endl;
		return -1;
	}
	 //初始化winsock2环境
	WSADATA wsa;
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
	{
		cerr << "init WinSock2.DLL Failed"<< endl;
		return -1;
	}
	//将命令行参数转换为IP地址
	u_long ulDestIP = inet_addr(argv[1]);\
	//主机名不为IP地址，进行域名解析
	if (ulDestIP == INADDR_NONE)
	{
	  //转换不成功时按域名解析
		hostent* pHostent = gethostbyname(argv[1]);
	    if (pHostent)
		{
			//获取IP地址
			ulDestIP = (*(in_addr*)pHostent->h_addr).s_addr;
			//输出屏幕信息
			cout << "The IP address of ultimate destination node:" << inet_ntoa(*(in_addr*)(&ulDestIP))<<endl;
		}
		else //解析主机名失败
		{
			cerr << "Failed to resolve the host name!" << argv[1] << endl;
			WSACleanup();
			return -1;
		}
	 }
	 else//为直接的IP地址
	 {
		//输出屏幕信息
		cout << "The IP address of ultimate destination node:" << argv[1] <<endl;
	 }

	 //填充目的Socket地址
	 sockaddr_in destSockAddr;
  	 //获取本机IP地址
	 PHOSTENT    hostinfo;
     char        name[255];

	 if(gethostname(name,sizeof(name)) == 0)
	 {
        if((hostinfo = gethostbyname(name))!= NULL)
		{
            ip = inet_ntoa(*(struct in_addr *)*hostinfo->h_addr_list);
			cout<<"The IP address of the source node          :"<<ip<<endl;
		}
	  }

	 ZeroMemory(&destSockAddr, sizeof(sockaddr_in));
	 destSockAddr.sin_family = AF_INET;
	 destSockAddr.sin_addr.s_addr = ulDestIP;

	 //使用ICMP协议创建Raw Socket SOCK_RAW表示使用原始套接字的方式
	 SOCKET sockRaw = WSASocket(AF_INET, SOCK_RAW, IPPROTO_ICMP, NULL, 0, WSA_FLAG_OVERLAPPED);
	 if (sockRaw == INVALID_SOCKET)
	 {
	   cerr << "ICMP failed to create scocked"<<endl;
	   WSACleanup();
	   return -1;
	 }

	 //设置端口属性
	 int iTimeout = DEF_ICMP_TIMEOUT;
	 if (setsockopt(sockRaw, SOL_SOCKET, SO_RCVTIMEO, (char*)&iTimeout, sizeof(iTimeout)) == SOCKET_ERROR)
	 {
  	   cerr << "Timeout!" << endl;
	   closesocket(sockRaw);
	   WSACleanup();
	   return -1;
	 }
	 //创建ICMP包发送缓冲区和接收缓冲区
	 char IcmpSendBuf[sizeof(ICMP_HEADER)+DEF_ICMP_DATA_SIZE];
	 memset(IcmpSendBuf, 0, sizeof(IcmpSendBuf));
	 char IcmpRecvBuf[MAX_ICMP_PACKET_SIZE];
	 memset(IcmpRecvBuf, 0, sizeof(IcmpRecvBuf));

	 //填充待发送的ICMP包
	 ICMP_HEADER* pIcmpHeader = (ICMP_HEADER*)IcmpSendBuf;
	 pIcmpHeader->type = ICMP_ECHO_REQUEST;
	 pIcmpHeader->code = 0;
	 pIcmpHeader->id = (USHORT)GetCurrentProcessId();
	 memset(IcmpSendBuf+sizeof(ICMP_HEADER), 'E', DEF_ICMP_DATA_SIZE);

	 //开始探测路由
	 DECODE_RESULT stDecodeResult;  //声明明解码结构结构体，便于后续输出路由信息
	 BOOL bReachDestHost = FALSE;
	 USHORT usSeqNo = 0;
	 int iTTL = 1;
	 int iMaxHop = DEF_MAX_HOP;
	 u_long tmp_dest_addr = 0;
	 while (!bReachDestHost && iMaxHop--)
	 {
		//设置IP数据报头的ttl字段
		setsockopt(sockRaw, IPPROTO_IP, IP_TTL, (char*)&iTTL, sizeof(iTTL));
		//填充ICMP数据报剩余字段
		((ICMP_HEADER*)IcmpSendBuf)->cksum = 0;
		((ICMP_HEADER*)IcmpSendBuf)->seq = htons(usSeqNo++);
		((ICMP_HEADER*)IcmpSendBuf)->cksum = GenerateChecksum((USHORT*)IcmpSendBuf, sizeof(ICMP_HEADER)+DEF_ICMP_DATA_SIZE);

		//记录序列号和当前时间
		stDecodeResult.usSeqNo = ((ICMP_HEADER*)IcmpSendBuf)->seq;
		stDecodeResult.dwRoundTripTime = GetTickCount();



		//设置循环ping的参数以及结果保存
		DWORD *icmp_time_counter = new DWORD[SEND_ICMP_TIMES];

		for(int i = 0 ; i < SEND_ICMP_TIMES; i++){

			//设置初始时间
			stDecodeResult.startTimeStamp = GetTickCount();//放入icmp循环体

			//发送ICMP的EchoRequest数据报
			if (sendto(sockRaw, IcmpSendBuf, sizeof(IcmpSendBuf), 0, (sockaddr*)&destSockAddr, sizeof(destSockAddr)) == SOCKET_ERROR)
			{
				//如果目的主机不可达则直接退出
				if (WSAGetLastError() == WSAEHOSTUNREACH)
				cout << "host can not reach,route end." << endl;
				closesocket(sockRaw);
				WSACleanup();
				return 0;
			}
			//接收ICMP的EchoReply数据报
			//因为收到的可能并非程序所期待的数据报，所以需要循环接收直到收到所要数据或超时
			sockaddr_in from;
			int iFromLen = sizeof(from);
			int iReadDataLen;

			while (1)
			{
				//等待数据到达
				iReadDataLen = recvfrom(sockRaw, IcmpRecvBuf, MAX_ICMP_PACKET_SIZE, 0, (sockaddr*)&from, &iFromLen);
				if (iReadDataLen != SOCKET_ERROR) //有数据包到达
				{
					//解码得到的数据包，如果解码正确则跳出接收循环发送下一个EchoRequest包
					if (DecodeIcmpResponse(IcmpRecvBuf, iReadDataLen, stDecodeResult))
					{
						if (stDecodeResult.dwIPaddr.s_addr == destSockAddr.sin_addr.s_addr)
						bReachDestHost = TRUE;
						//设置每一次的往返时间到数组中
						icmp_time_counter[i] = stDecodeResult.rtt;
						break;
					}
				}
				else if (WSAGetLastError() == WSAETIMEDOUT) //接收超时，打印星号
				{
					//如果是timeout 那么设置其rtt时间为-1，标注该次ping不成功，最后计算平均值的时候直接略过
					icmp_time_counter[i] = -1;
					break;
				}
				else
				{
					cerr << "Accepting packet error" << endl;
					closesocket(sockRaw);
					WSACleanup();
					return -1;
				}
			}// end while
		}// end send icmp iteration

		//遍历找出time out的值
		for(int j = 0; j < SEND_ICMP_TIMES; j++){//4294967295
			if(icmp_time_counter[j] == 4294967295)
				icmp_time_counter[j] = -1;
		}
		//计算平均值以及方差并且打印输出
		unsigned long sum = 0;
		int counter = SEND_ICMP_TIMES;
		for(int j = 0; j < SEND_ICMP_TIMES; j++){//4294967295
			if(icmp_time_counter[j] >= 0 && icmp_time_counter[j] != 4294967295)
				sum += icmp_time_counter[j];
			else
				counter -= 1;
		}
		unsigned long avg = 0;

		//标志着当前目标ip地址不可ping到
		bool is_reachable = true;

		//输出当前跳站数作为路由信息序号
		cout <<"Router "<< iTTL<<": ";//(*(in_addr*)pHostent->h_addr).s_addr inet_ntoa(*(in_addr*)(&ulDestIP))
		u_long source_addr = stDecodeResult.hostinfo.S_un.S_addr;
		u_long dest_addr = stDecodeResult.dwIPaddr.S_un.S_addr;
		if(tmp_dest_addr != dest_addr)
			tmp_dest_addr = dest_addr;
		else
			// 目标ip不存在
			is_reachable = false;

	    unsigned char source_ip[4];//可以用4个unsigned char来保存IP，数据范围0~255
	    unsigned char dest_ip[4];//可以用4个unsigned char来保存IP，数据范围0~255

	    //获取原地址ip
	    for (int j = 0;j < 4;++j)
	    {
	        unsigned long temp = source_addr << (2 * j) * 4; //每次先把需要ip数据移到最左边
	        temp = temp >> 6 * 4; //然后把最左边的两位移到最低位
	        source_ip[j] = (unsigned char )temp ; //强制转换成unsigned char保存
	    }
	    //获取目标地址ip
	    for (int j = 0;j < 4;++j)
	    {
	        unsigned long temp = dest_addr << (2 * j) * 4; //每次先把需要ip数据移到最左边
	        temp = temp >> 6 * 4; //然后把最左边的两位移到最低位
	        dest_ip[j] = (unsigned char )temp ; //强制转换成unsigned char保存
	    }

		cout<<"The RRT between ";
		//输出源地址
		for(int j = 3 ; j >= 0; j--){
			if(j != 0)
				cout<<int(source_ip[j])<<'.';
			else
				cout<<int(source_ip[j]);
		}

		cout<<" and ";
		if(is_reachable){
			//输出目标地址
			for(int j = 3 ; j >= 0; j--){
				if(j != 0)
					cout<<int(dest_ip[j])<<'.';
				else
					cout<<int(dest_ip[j]);
			}
		}
		else //目标ip不存在输出*号
			cout<<'*';

		cout<<endl;

		//输出每次发送的icmp报的rtt
		cout<<'\t';
		for(int j = 0; j < SEND_ICMP_TIMES; j++){
			if(icmp_time_counter[j] >= 0 && icmp_time_counter[j] != 4294967295)//排除超时
				cout<<setw(8)<<icmp_time_counter[j]<<" ms";
			else
				cout<<setw(8)<<"* ms";
		}
		//换行
		cout<<endl;
		//输出平均值以及
		if(counter != 0)
		{

			avg = sum / counter;
			//计算方差
			sum = 0;
			for(int j = 0; j < SEND_ICMP_TIMES; j++)
				if(icmp_time_counter[j] >= 0 && icmp_time_counter[j] != 4294967295)
					sum += (icmp_time_counter[j] - avg) * (icmp_time_counter[j] - avg);
			unsigned long std = sqrt(sum / counter);

			cout<<"\t Avg :"<<setw(4)<< avg << " ms, Std : "<<setw(4)<< std <<" ms."<<endl;
		}
		else{
			cout<<"\t Time out, avg and std of RTT is not exist."<<endl;
		}

	    //TTL值加1
		iTTL++;
	 }
	 //输出屏幕信息
	 closesocket(sockRaw);
	 WSACleanup();
	 return 0;
}
//产生网际校验和
USHORT GenerateChecksum(USHORT* pBuf, int iSize)
{
	 unsigned long cksum = 0;
	 while (iSize>1)
	 {
	    cksum += *pBuf++;
	    iSize -= sizeof(USHORT);
	 }
	 if (iSize)
	    cksum += *(UCHAR*)pBuf;
	 cksum = (cksum >> 16) + (cksum & 0xffff);
	 cksum += (cksum >> 16);
	 return (USHORT)(~cksum);
}

//解码得到的数据报
BOOL DecodeIcmpResponse(char* pBuf, int iPacketSize, DECODE_RESULT& stDecodeResult)
{
	 //检查数据报大小的合法性
	 IP_HEADER* pIpHdr = (IP_HEADER*)pBuf;
	 int iIpHdrLen = pIpHdr->hdr_len * 4;
	 if (iPacketSize < (int)(iIpHdrLen+sizeof(ICMP_HEADER)))
	     return FALSE;
	 //按照ICMP包类型检查id字段和序列号以确定是否是程序应接收的Icmp包
	 ICMP_HEADER* pIcmpHdr = (ICMP_HEADER*)(pBuf+iIpHdrLen);
	 USHORT usID, usSquNo;
	 if (pIcmpHdr->type == ICMP_ECHO_REPLY)
	 {
	    usID = pIcmpHdr->id;
	    usSquNo = pIcmpHdr->seq;
	 }
	 else if(pIcmpHdr->type == ICMP_TIMEOUT)
	 {
	    char* pInnerIpHdr = pBuf+iIpHdrLen+sizeof(ICMP_HEADER);  //载荷中的IP头
	    int iInnerIPHdrLen = ((IP_HEADER*)pInnerIpHdr)->hdr_len * 4;//载荷中的IP头长
	    ICMP_HEADER* pInnerIcmpHdr = (ICMP_HEADER*)(pInnerIpHdr+iInnerIPHdrLen);//载荷中的ICMP头
	    usID = pInnerIcmpHdr->id;
	    usSquNo = pInnerIcmpHdr->seq;
	 }
	 else
	    return FALSE;
	 if (usID != (USHORT)GetCurrentProcessId() || usSquNo !=stDecodeResult.usSeqNo)
	    return FALSE;
	 //处理正确收到的ICMP数据报
	 if (pIcmpHdr->type == ICMP_ECHO_REPLY ||
	 pIcmpHdr->type == ICMP_TIMEOUT)
	 {
	  //返回解码结果
	    stDecodeResult.dwIPaddr.s_addr = pIpHdr->sourceIP;
	    stDecodeResult.hostinfo.s_addr = pIpHdr->destIP;
	    stDecodeResult.rtt = GetTickCount()-stDecodeResult.startTimeStamp;
	    //cout<<"log: "<<stDecodeResult.rtt<<endl;
	    return TRUE;
	 }
	 return FALSE;
 }
