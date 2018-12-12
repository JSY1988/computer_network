#ifndef _ITRACERT_H_//��ֹ�ظ�����ͷ�ļ�
#define _ITRACERT_H_

//IP���ݱ��ײ�
typedef struct
{
 unsigned char hdr_len :4;  // �ײ�����
 unsigned char version :4;  // �汾��
 unsigned char tos;   // ��������
 unsigned short total_len;  // �ܳ���
 unsigned short identifier;  // ��ʶ
 unsigned short frag_and_flags; //��־��ƫ�� 
 unsigned char ttl;   // ����ʱ��
 unsigned char protocol;  // Э��
 unsigned short checksum;  // �ײ�У���
 unsigned long sourceIP;  // ԴIP
 unsigned long destIP;   // Ŀ��IP
} IP_HEADER;

LPCSTR ip ;

//ICMP�����ײ�
typedef struct
{
 BYTE type;  //8λ����
 BYTE code;  //8λ����
 USHORT cksum;  //16λУ���
 USHORT id;   //16λ��ʶ��
 USHORT seq;  //16λ���к�
} ICMP_HEADER;

//������
typedef struct
{
 USHORT usSeqNo;   //�����к�
 DWORD dwRoundTripTime; //����ʱ��
 DWORD startTimeStamp;	//��ʼʱ��
 in_addr dwIPaddr,hostinfo;  //�Զ�IP��ַ,����IP
 DWORD rtt;   		//����ʱ��

} DECODE_RESULT;

//ICMP�����ֶ�
const BYTE ICMP_ECHO_REQUEST = 8; //�������
const BYTE ICMP_ECHO_REPLY  = 0; //����Ӧ��
const BYTE ICMP_TIMEOUT   = 11; //���䳬ʱ
const DWORD DEF_ICMP_TIMEOUT = 3000; //Ĭ�ϳ�ʱʱ�䣬��λms
const int DEF_ICMP_DATA_SIZE = 32; //Ĭ��ICMP���ݲ��ֳ���
const int MAX_ICMP_PACKET_SIZE = 1024; //���ICMP���ݱ��Ĵ�С
const int DEF_MAX_HOP = 20;    //�����վ��

const int SEND_ICMP_TIMES = 4;		//����icmp���Ĵ���������ͳ�ƾ�ֵ�ͷ���

USHORT GenerateChecksum(USHORT* pBuf, int iSize);
BOOL DecodeIcmpResponse(char* pBuf, int iPacketSize, DECODE_RESULT& stDecodeResult);
// int calculateTheAvgAndAtd

#endif // _ITRACERT_H_ 
