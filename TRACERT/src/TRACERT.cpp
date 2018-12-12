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

	 //�ж������в����Ƿ���ȷ����ip������ַ
	if (argc != 2)
	{
		cerr << "please enter true arg"<<endl;
		return -1;
	}
	 //��ʼ��winsock2����
	WSADATA wsa;
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
	{
		cerr << "init WinSock2.DLL Failed"<< endl;
		return -1;
	}
	//�������в���ת��ΪIP��ַ
	u_long ulDestIP = inet_addr(argv[1]);\
	//��������ΪIP��ַ��������������
	if (ulDestIP == INADDR_NONE)
	{
	  //ת�����ɹ�ʱ����������
		hostent* pHostent = gethostbyname(argv[1]);
	    if (pHostent)
		{
			//��ȡIP��ַ
			ulDestIP = (*(in_addr*)pHostent->h_addr).s_addr;
			//�����Ļ��Ϣ
			cout << "The IP address of ultimate destination node:" << inet_ntoa(*(in_addr*)(&ulDestIP))<<endl;
		}
		else //����������ʧ��
		{
			cerr << "Failed to resolve the host name!" << argv[1] << endl;
			WSACleanup();
			return -1;
		}
	 }
	 else//Ϊֱ�ӵ�IP��ַ
	 {
		//�����Ļ��Ϣ
		cout << "The IP address of ultimate destination node:" << argv[1] <<endl;
	 }

	 //���Ŀ��Socket��ַ
	 sockaddr_in destSockAddr;
  	 //��ȡ����IP��ַ
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

	 //ʹ��ICMPЭ�鴴��Raw Socket SOCK_RAW��ʾʹ��ԭʼ�׽��ֵķ�ʽ
	 SOCKET sockRaw = WSASocket(AF_INET, SOCK_RAW, IPPROTO_ICMP, NULL, 0, WSA_FLAG_OVERLAPPED);
	 if (sockRaw == INVALID_SOCKET)
	 {
	   cerr << "ICMP failed to create scocked"<<endl;
	   WSACleanup();
	   return -1;
	 }

	 //���ö˿�����
	 int iTimeout = DEF_ICMP_TIMEOUT;
	 if (setsockopt(sockRaw, SOL_SOCKET, SO_RCVTIMEO, (char*)&iTimeout, sizeof(iTimeout)) == SOCKET_ERROR)
	 {
  	   cerr << "Timeout!" << endl;
	   closesocket(sockRaw);
	   WSACleanup();
	   return -1;
	 }
	 //����ICMP�����ͻ������ͽ��ջ�����
	 char IcmpSendBuf[sizeof(ICMP_HEADER)+DEF_ICMP_DATA_SIZE];
	 memset(IcmpSendBuf, 0, sizeof(IcmpSendBuf));
	 char IcmpRecvBuf[MAX_ICMP_PACKET_SIZE];
	 memset(IcmpRecvBuf, 0, sizeof(IcmpRecvBuf));

	 //�������͵�ICMP��
	 ICMP_HEADER* pIcmpHeader = (ICMP_HEADER*)IcmpSendBuf;
	 pIcmpHeader->type = ICMP_ECHO_REQUEST;
	 pIcmpHeader->code = 0;
	 pIcmpHeader->id = (USHORT)GetCurrentProcessId();
	 memset(IcmpSendBuf+sizeof(ICMP_HEADER), 'E', DEF_ICMP_DATA_SIZE);

	 //��ʼ̽��·��
	 DECODE_RESULT stDecodeResult;  //����������ṹ�ṹ�壬���ں������·����Ϣ
	 BOOL bReachDestHost = FALSE;
	 USHORT usSeqNo = 0;
	 int iTTL = 1;
	 int iMaxHop = DEF_MAX_HOP;
	 u_long tmp_dest_addr = 0;
	 while (!bReachDestHost && iMaxHop--)
	 {
		//����IP���ݱ�ͷ��ttl�ֶ�
		setsockopt(sockRaw, IPPROTO_IP, IP_TTL, (char*)&iTTL, sizeof(iTTL));
		//���ICMP���ݱ�ʣ���ֶ�
		((ICMP_HEADER*)IcmpSendBuf)->cksum = 0;
		((ICMP_HEADER*)IcmpSendBuf)->seq = htons(usSeqNo++);
		((ICMP_HEADER*)IcmpSendBuf)->cksum = GenerateChecksum((USHORT*)IcmpSendBuf, sizeof(ICMP_HEADER)+DEF_ICMP_DATA_SIZE);

		//��¼���кź͵�ǰʱ��
		stDecodeResult.usSeqNo = ((ICMP_HEADER*)IcmpSendBuf)->seq;
		stDecodeResult.dwRoundTripTime = GetTickCount();



		//����ѭ��ping�Ĳ����Լ��������
		DWORD *icmp_time_counter = new DWORD[SEND_ICMP_TIMES];

		for(int i = 0 ; i < SEND_ICMP_TIMES; i++){

			//���ó�ʼʱ��
			stDecodeResult.startTimeStamp = GetTickCount();//����icmpѭ����

			//����ICMP��EchoRequest���ݱ�
			if (sendto(sockRaw, IcmpSendBuf, sizeof(IcmpSendBuf), 0, (sockaddr*)&destSockAddr, sizeof(destSockAddr)) == SOCKET_ERROR)
			{
				//���Ŀ���������ɴ���ֱ���˳�
				if (WSAGetLastError() == WSAEHOSTUNREACH)
				cout << "host can not reach,route end." << endl;
				closesocket(sockRaw);
				WSACleanup();
				return 0;
			}
			//����ICMP��EchoReply���ݱ�
			//��Ϊ�յ��Ŀ��ܲ��ǳ������ڴ������ݱ���������Ҫѭ������ֱ���յ���Ҫ���ݻ�ʱ
			sockaddr_in from;
			int iFromLen = sizeof(from);
			int iReadDataLen;

			while (1)
			{
				//�ȴ����ݵ���
				iReadDataLen = recvfrom(sockRaw, IcmpRecvBuf, MAX_ICMP_PACKET_SIZE, 0, (sockaddr*)&from, &iFromLen);
				if (iReadDataLen != SOCKET_ERROR) //�����ݰ�����
				{
					//����õ������ݰ������������ȷ����������ѭ��������һ��EchoRequest��
					if (DecodeIcmpResponse(IcmpRecvBuf, iReadDataLen, stDecodeResult))
					{
						if (stDecodeResult.dwIPaddr.s_addr == destSockAddr.sin_addr.s_addr)
						bReachDestHost = TRUE;
						//����ÿһ�ε�����ʱ�䵽������
						icmp_time_counter[i] = stDecodeResult.rtt;
						break;
					}
				}
				else if (WSAGetLastError() == WSAETIMEDOUT) //���ճ�ʱ����ӡ�Ǻ�
				{
					//�����timeout ��ô������rttʱ��Ϊ-1����ע�ô�ping���ɹ���������ƽ��ֵ��ʱ��ֱ���Թ�
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

		//�����ҳ�time out��ֵ
		for(int j = 0; j < SEND_ICMP_TIMES; j++){//4294967295
			if(icmp_time_counter[j] == 4294967295)
				icmp_time_counter[j] = -1;
		}
		//����ƽ��ֵ�Լ�����Ҵ�ӡ���
		unsigned long sum = 0;
		int counter = SEND_ICMP_TIMES;
		for(int j = 0; j < SEND_ICMP_TIMES; j++){//4294967295
			if(icmp_time_counter[j] >= 0 && icmp_time_counter[j] != 4294967295)
				sum += icmp_time_counter[j];
			else
				counter -= 1;
		}
		unsigned long avg = 0;

		//��־�ŵ�ǰĿ��ip��ַ����ping��
		bool is_reachable = true;

		//�����ǰ��վ����Ϊ·����Ϣ���
		cout <<"Router "<< iTTL<<": ";//(*(in_addr*)pHostent->h_addr).s_addr inet_ntoa(*(in_addr*)(&ulDestIP))
		u_long source_addr = stDecodeResult.hostinfo.S_un.S_addr;
		u_long dest_addr = stDecodeResult.dwIPaddr.S_un.S_addr;
		if(tmp_dest_addr != dest_addr)
			tmp_dest_addr = dest_addr;
		else
			// Ŀ��ip������
			is_reachable = false;

	    unsigned char source_ip[4];//������4��unsigned char������IP�����ݷ�Χ0~255
	    unsigned char dest_ip[4];//������4��unsigned char������IP�����ݷ�Χ0~255

	    //��ȡԭ��ַip
	    for (int j = 0;j < 4;++j)
	    {
	        unsigned long temp = source_addr << (2 * j) * 4; //ÿ���Ȱ���Ҫip�����Ƶ������
	        temp = temp >> 6 * 4; //Ȼ�������ߵ���λ�Ƶ����λ
	        source_ip[j] = (unsigned char )temp ; //ǿ��ת����unsigned char����
	    }
	    //��ȡĿ���ַip
	    for (int j = 0;j < 4;++j)
	    {
	        unsigned long temp = dest_addr << (2 * j) * 4; //ÿ���Ȱ���Ҫip�����Ƶ������
	        temp = temp >> 6 * 4; //Ȼ�������ߵ���λ�Ƶ����λ
	        dest_ip[j] = (unsigned char )temp ; //ǿ��ת����unsigned char����
	    }

		cout<<"The RRT between ";
		//���Դ��ַ
		for(int j = 3 ; j >= 0; j--){
			if(j != 0)
				cout<<int(source_ip[j])<<'.';
			else
				cout<<int(source_ip[j]);
		}

		cout<<" and ";
		if(is_reachable){
			//���Ŀ���ַ
			for(int j = 3 ; j >= 0; j--){
				if(j != 0)
					cout<<int(dest_ip[j])<<'.';
				else
					cout<<int(dest_ip[j]);
			}
		}
		else //Ŀ��ip���������*��
			cout<<'*';

		cout<<endl;

		//���ÿ�η��͵�icmp����rtt
		cout<<'\t';
		for(int j = 0; j < SEND_ICMP_TIMES; j++){
			if(icmp_time_counter[j] >= 0 && icmp_time_counter[j] != 4294967295)//�ų���ʱ
				cout<<setw(8)<<icmp_time_counter[j]<<" ms";
			else
				cout<<setw(8)<<"* ms";
		}
		//����
		cout<<endl;
		//���ƽ��ֵ�Լ�
		if(counter != 0)
		{

			avg = sum / counter;
			//���㷽��
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

	    //TTLֵ��1
		iTTL++;
	 }
	 //�����Ļ��Ϣ
	 closesocket(sockRaw);
	 WSACleanup();
	 return 0;
}
//��������У���
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

//����õ������ݱ�
BOOL DecodeIcmpResponse(char* pBuf, int iPacketSize, DECODE_RESULT& stDecodeResult)
{
	 //������ݱ���С�ĺϷ���
	 IP_HEADER* pIpHdr = (IP_HEADER*)pBuf;
	 int iIpHdrLen = pIpHdr->hdr_len * 4;
	 if (iPacketSize < (int)(iIpHdrLen+sizeof(ICMP_HEADER)))
	     return FALSE;
	 //����ICMP�����ͼ��id�ֶκ����к���ȷ���Ƿ��ǳ���Ӧ���յ�Icmp��
	 ICMP_HEADER* pIcmpHdr = (ICMP_HEADER*)(pBuf+iIpHdrLen);
	 USHORT usID, usSquNo;
	 if (pIcmpHdr->type == ICMP_ECHO_REPLY)
	 {
	    usID = pIcmpHdr->id;
	    usSquNo = pIcmpHdr->seq;
	 }
	 else if(pIcmpHdr->type == ICMP_TIMEOUT)
	 {
	    char* pInnerIpHdr = pBuf+iIpHdrLen+sizeof(ICMP_HEADER);  //�غ��е�IPͷ
	    int iInnerIPHdrLen = ((IP_HEADER*)pInnerIpHdr)->hdr_len * 4;//�غ��е�IPͷ��
	    ICMP_HEADER* pInnerIcmpHdr = (ICMP_HEADER*)(pInnerIpHdr+iInnerIPHdrLen);//�غ��е�ICMPͷ
	    usID = pInnerIcmpHdr->id;
	    usSquNo = pInnerIcmpHdr->seq;
	 }
	 else
	    return FALSE;
	 if (usID != (USHORT)GetCurrentProcessId() || usSquNo !=stDecodeResult.usSeqNo)
	    return FALSE;
	 //������ȷ�յ���ICMP���ݱ�
	 if (pIcmpHdr->type == ICMP_ECHO_REPLY ||
	 pIcmpHdr->type == ICMP_TIMEOUT)
	 {
	  //���ؽ�����
	    stDecodeResult.dwIPaddr.s_addr = pIpHdr->sourceIP;
	    stDecodeResult.hostinfo.s_addr = pIpHdr->destIP;
	    stDecodeResult.rtt = GetTickCount()-stDecodeResult.startTimeStamp;
	    //cout<<"log: "<<stDecodeResult.rtt<<endl;
	    return TRUE;
	 }
	 return FALSE;
 }
