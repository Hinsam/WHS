#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>

/* Ethernet header 이더넷 헤더 정보를 저장하는 구조체*/
struct ethheader {
  u_char  ether_dhost[6]; /* destination host address 목적지 호스트의 MAC 주소*/
  u_char  ether_shost[6]; /* source host address 소스 호스트의 MAC 주소*/
  u_short ether_type;     /* protocol type (IP, ARP, RARP, etc) 이더넷 프레임에 포함된 상위 계층 프로토콜, IP프로토콜의 경우에는 0x0800*/
};

/* IP Header IP 헤더 정보를 저장하는 구조체*/
struct ipheader {
  unsigned char      iph_ihl:4, //IP header length, ip헤더의 길이
                     iph_ver:4; //IP version, ip버전, ipv4와 ipv6중 하나를 나타냄
  unsigned char      iph_tos; //Type of service, 서비스 유형, ip패킷에 대한 특정 서비스 수준 지정
  unsigned short int iph_len; //IP Packet length (data + header), ip패킷의 전체 길이, 헤더와 데이터를 모두 포함한다.
  unsigned short int iph_ident; //Identification, 패킷의 식별자, 패킷의 조각화 및 재조립에 사용된다.
  unsigned short int iph_flag:3, //Fragmentation flags, 패킷의 조각화 플래그를 나타낸다. 패킷이 조각화 되었는지여부를 나타냄
                     iph_offset:13; //Flags offset, 조각화된 패킷의 오프셋을 나타냄
  unsigned char      iph_ttl; //Time to Live, 패킷의 Time to Live를 나타냄, 이 값은 패킷이 라우터를 통과할 때마다 감소하며 0이 되면 폐기
  unsigned char      iph_protocol; //Protocol type, 패킷의 상위 계층 프로토콜 tcp는 6, udp는 17
  unsigned short int iph_chksum; //IP datagram checksum, 데이터의 무결성 검증
  struct  in_addr    iph_sourceip; //Source IP address, 소스 ip주소
  struct  in_addr    iph_destip;   //Destination IP address, 목적지 ip주소
};

// TCP Headr tcp 헤더 정보를 저장하는 구조체
struct tcpheader {
    u_short tcp_sport;               /* source port */
    u_short tcp_dport;               /* destination port */
    u_int   tcp_seq;                 /* sequence number */
    u_int   tcp_ack;                 /* acknowledgement number */
    u_char  tcp_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcp_win;                 /* window */
    u_short tcp_sum;                 /* checksum */
    u_short tcp_urp;                 /* urgent pointer */
};

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet)
{
    //패킷 포인터를 이더넷 헤더 구조체로 캐스팅한다.
    struct ethheader *eth = (struct ethheader *)packet;
    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

    if (ip->iph_protocol == IPPROTO_TCP) {
        printf("======================Packet capture======================\n");
        printf("----------------------Mac Address----------------------\n");
        printf("Source MAC Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
        printf("Destination MAC Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

        printf("----------------------IP Address----------------------\n");
        printf("iph_sourceip            : %s\n", inet_ntoa(ip->iph_sourceip));
        printf("iph_destip              : %s\n", inet_ntoa(ip->iph_destip));

        printf("----------------------TCP Address----------------------\n");
        struct tcpheader *th = (struct tcpheader *)(packet + sizeof(struct ethheader) + (ip->iph_ihl * 4));
        printf("TCP source Port         : %d\n", ntohs(th->tcp_sport));
        printf("TCP destination Port    : %d\n", ntohs(th->tcp_dport));

        //output the right size message
        u_char *message = (u_char *)(packet + sizeof(struct ethheader)) + (ip->iph_ihl * 4) + (TH_OFF(th));
        printf("---------------------Message(16)----------------------\n");
        for (int i = 0; i < 100; i++) {
            if (i % 10 == 0 && i != 0) { printf("\n"); }
            printf("%.2X ", message[i]);
        }
        printf("\n-------------------Message(str)----------------------\n");
        for (int i = 0; i < 100; i++) {
            if (i % 50 == 0 && i != 0) { printf("\n"); }
            printf("%c", message[i]);
        }
        printf("\n\n");
    } else {
        printf("Not TCP packet.\n");
    }
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name enp0s3
  handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);
  if (pcap_setfilter(handle, &fp) !=0) {
      pcap_perror(handle, "Error:");
      exit(EXIT_FAILURE);
  }

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);   //Close the handle
  return 0;
}

