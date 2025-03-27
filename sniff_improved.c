#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <ctype.h>
#include "myheader.h"

const int MAX_LEN = 256;

void print_mac(const u_int8_t *mac){
  for(int i = 0; i < 6; i ++){
    printf("%02x:", mac[i]);
    if(i == 5) printf("%02x", mac[i]);
  }
}

void got_packet(uint8_t *args, const struct pcap_pkthdr *header,
                              const uint8_t *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;
  int eth_size = sizeof(struct ethheader);
  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
    struct ipheader * ip = (struct ipheader *)
                           (packet + eth_size); 
    int ip_size = ip->iph_ihl*4;
    /* determine protocol */
    if(ip->iph_protocol == IPPROTO_TCP) {
      struct tcpheader *tcp = (struct tcpheader *)(packet + eth_size + ip_size);
      int tcp_size = TH_OFF(tcp)*4;
      const uint8_t *payload = packet + eth_size + ip_size + tcp_size;
      int payload_len = ntohs(ip->iph_len) - ip_size - tcp_size;
      printf("Ethernet Header Info\n");
      printf("src mac : "); print_mac(eth->ether_shost); printf("\n");
      printf("dst mac : "); print_mac(eth->ether_dhost); printf("\n");
      printf("-------------------------\n");
      printf("IP Header Info\n");
      printf("src ip : %s\n", inet_ntoa(ip->iph_sourceip));
      printf("dst ip : %s\n", inet_ntoa(ip->iph_destip));
      printf("-------------------------\n");
      printf("TCP Header Info\n");
      printf("src port : %d\n", ntohs(tcp->tcp_sport));
      printf("dst port : %d\n", ntohs(tcp->tcp_dport));
      printf("-------------------------\n");
      printf("Massege Info\n");
      printf("string : ");
      
      payload_len = payload_len > MAX_LEN ? MAX_LEN : payload_len;
      for(int i = 0; i < payload_len; i++){
        if(isprint(payload[i]))
          printf("%c", payload[i]);
        else
          printf(".");
      }
      printf("\n");
      printf("HEX : ");
      for(int i = 0; i < payload_len; i++){
        printf("%02x ", payload[i]);
        if((i+1)%16 == 0) printf("\n");
      }
      printf("\n");
      printf("============================\n");
    }
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
  handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

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


