/*
*Timothy Kuo
*tyk3
*proj3.cpp
*Created on 4/7/17
*This file completes a packet trace of an input trace file.  It con do different things based on
*the command that is given.  The possible commands are: -p, -s, -t that do the following
*respectively: dumps all the packets that include information on src and dest ip, protocol,
*and seq/ack numbers, connection summaries that shows resp to orig and orig to resp packets
*between different protocols, shows round trip times between two endpoints.
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <string>
#include <map>
#include <set>

#define ETHER_ADDR_LEN 6
#define UDP_HEADER_LEN 8
#define MIN_TCP_HDR_LEN 20
#define MAX_TCP_HDR_LEN 60
#define IP 2048
#define numEleRead 1
#define TCP 6
#define UDP 17
#define MICROSECS_PER_SEC 1000000.0
#define MAX_ETH_PKT 1518
#define IP_WORD_SIZE 4
#define TCP_WORD_SIZE 4

FILE* traceFile = NULL;
bool pktDump = false;
bool connSumms = false;
bool roundTripTimes = false;

struct pktinfo {
    unsigned int sec, usec;
    unsigned short caplen, ignored;
};

struct	etherHeader {
	u_char	etherDHost[ETHER_ADDR_LEN];
	u_char	etherSHost[ETHER_ADDR_LEN];
	u_short	etherType;
};

struct pktsum {
 struct pktinfo meta;
 unsigned char pkt [MAX_ETH_PKT];
 struct etherHeader *ethh;
 struct ip *iph;
 unsigned short ipHdrLen;
 unsigned short ipLen;
 struct udphdr *udph;
 struct tcphdr *tcph;
 unsigned short tcpHdrLen;
 double ts;
 unsigned short appDataVol;
};

struct connection {
  std::string srcIp;
  u_short srcPort;
  std::string dstIp;
  u_short dstPort;
};

struct connectInfo {
  double ts;
  double dur;
  u_char proto;
  int oToRPkts;
  int rToOPkts;
  unsigned long oToRBytes;
  unsigned long rToOBytes;
};

struct roundTripInfo {
  tcp_seq oToRSeq;
  bool oToRAck;
  tcp_seq rToOSeq;
  bool rToOAck;
  double oToRTs;
  double oToRRtt;
  double rToOTs;
  double rToORtt;
  unsigned short oToRBytes;
  unsigned short rToOBytes;
};

bool next_packet (struct pktsum *pkts) {
  //read meta information
  if (sizeof(pkts->meta) != sizeof (struct pktinfo))
    perror ("error reading meta information");
  pkts->meta.sec = ntohl (pkts->meta.sec);
  pkts->meta.usec = ntohl (pkts->meta.usec);
  pkts->meta.caplen = ntohs (pkts->meta.caplen);
  pkts->ts = pkts->meta.sec + (pkts->meta.usec / MICROSECS_PER_SEC);
  //if nothing in the packet
  if (pkts->meta.caplen == 0)
    return false;
  //if pkt larger than max size
  if (pkts->meta.caplen > MAX_ETH_PKT)
    perror ("caplen > maximum ethernet frame; exitting\n");
  //read rest of the packet into pkts.pkt
  if (numEleRead != fread (pkts->pkt, pkts->meta.caplen, 1, traceFile))
    perror ("error reading packet data from trace file\n");
  //if full ether header is there
  if (pkts->meta.caplen < sizeof (struct etherHeader))
    return false;
  pkts->ethh = (struct etherHeader *)pkts->pkt;
  pkts->ethh->etherType = ntohs (pkts->ethh->etherType);
  if (pkts->meta.caplen == sizeof (struct etherHeader))
    return false;
  if (pkts->ethh->etherType != IP)
    return false;
  pkts->iph = (struct ip *)(pkts->pkt + sizeof (struct etherHeader));
  pkts->ipHdrLen = pkts->iph->ip_hl * IP_WORD_SIZE;
  //if ip header is truncated
  if (pkts->meta.caplen < (sizeof (struct etherHeader) + pkts->ipHdrLen)) {
    //mark as NULL for later to see if IP is truncated
    pkts->iph = NULL;
    return false;
  }
  pkts->ipLen = ntohs (pkts->iph->ip_len);
  //read IP protocol
  if (pkts->iph->ip_p == TCP) {
    pkts->tcph = (struct tcphdr *)(pkts->pkt +
                                    sizeof (struct etherHeader) +
                                    pkts->ipHdrLen);
    pkts->tcpHdrLen = pkts->tcph->th_off*TCP_WORD_SIZE;
    //tcp header is between min and max length
    if(pkts->tcpHdrLen < MIN_TCP_HDR_LEN || pkts->tcpHdrLen > MAX_TCP_HDR_LEN)
      return false;
    //check if TCP hdr is truncated
    if(pkts->meta.caplen < sizeof (struct etherHeader) + pkts->ipHdrLen + pkts->tcpHdrLen)
      return false;
    pkts->appDataVol = pkts->ipLen - pkts->ipHdrLen - pkts->tcpHdrLen;
  } else if(pkts->iph->ip_p == UDP) {
    pkts->udph = (struct udphdr *)(pkts->pkt +
                                    sizeof (struct etherHeader) +
                                    pkts->ipHdrLen);
    //check if UDP header is truncated
    if(pkts->meta.caplen < sizeof (struct etherHeader) + pkts->ipHdrLen + UDP_HEADER_LEN)
      return false;
    pkts->appDataVol = pkts->ipLen - pkts->ipHdrLen - UDP_HEADER_LEN;
  } else {
    return false;
  }

  return true;
}

void printConnSumms(std::map<std::pair<std::string, std::string>, connectInfo> connectionsTable) {

  std::map<std::pair<std::string, std::string>, connectInfo>::iterator it;

  for (it = connectionsTable.begin(); it != connectionsTable.end(); it++ ) {
    if(it->second.proto == UDP) {
      printf("%f %f %s U %d %lu ", it->second.ts, it->second.dur, it->first.first.c_str(), it->second.oToRPkts, it->second.oToRBytes);
      if(it->second.rToOPkts == 0) {
        printf("? ?\n");
      }
      else {
        printf("%d %lu\n", it->second.rToOPkts, it->second.rToOBytes);
      }
    }
    else if(it->second.proto == TCP) {
      printf("%f %f %s T %d %lu ", it->second.ts, it->second.dur, it->first.first.c_str(), it->second.oToRPkts, it->second.oToRBytes);
      if(it->second.rToOPkts == 0) {
        printf("? ?\n");
      }
      else {
        printf("%d %lu\n", it->second.rToOPkts, it->second.rToOBytes);
      }
    }
  }
}

void printRoundTripTimes(std::map<std::pair<std::string, std::string>, roundTripInfo> roundTripTimesTable) {
  std::map<std::pair<std::string, std::string>, roundTripInfo>::iterator it;

  for (it = roundTripTimesTable.begin(); it != roundTripTimesTable.end(); it++) {
    printf("%s ", it->first.first.c_str());
    if(it->second.oToRBytes == 0) {
      printf("- ");
    }
    else if(it->second.oToRAck == false) {
      printf("? ");
    }
    else {
      printf("%f ", it->second.oToRRtt);
    }

    if(it->second.rToOBytes == 0) {
      printf("-\n");
    }
    else if(it->second.rToOAck == false) {
      printf("?\n");
    }
    else {
      printf("%f\n", it->second.rToORtt);
    }
  }
}

void trace() {
  //12 bytes of meta info in each packet
  struct pktsum psummary;
  std::map<std::pair<std::string, std::string>, connectInfo> connectionsTable;
  std::map<std::pair<std::string, std::string>, roundTripInfo> roundTripTimesTable;
  //can't store pktsum, store somethign else
  //while succesfully read meta info
  while(numEleRead == fread (&psummary.meta, sizeof(struct pktinfo), 1, traceFile)) {
    if(pktDump && next_packet(&psummary)) {
      //printf("pkt num: %d\n", counter);
      printf("%f ", psummary.ts);
      printf("%s ", inet_ntoa(psummary.iph->ip_src));
      if(psummary.iph->ip_p == TCP) {
        printf("%d ", ntohs(psummary.tcph->th_sport));
        printf("%s ", inet_ntoa(psummary.iph->ip_dst));
        printf("%d ", ntohs(psummary.tcph->th_dport));
        printf("T ");
        printf("%d ", psummary.appDataVol);
        printf("%u ", ntohl(psummary.tcph->th_seq));
        printf("%u\n", ntohl(psummary.tcph->th_ack));
      }
      if(psummary.iph->ip_p == UDP) {
        printf("%d ", ntohs(psummary.udph->uh_sport));
        printf("%s ", inet_ntoa(psummary.iph->ip_dst));
        printf("%d ", ntohs(psummary.udph->uh_dport));
        printf("U ");
        printf("%d\n", psummary.appDataVol);
      }
    }
    else if(connSumms && next_packet(&psummary)) {
      //store psummary ip src and port as string, ip dst and port as string

      //make connection
      std::string connection;
      std::string connectionReverse;
      struct connectInfo connectInfo;
      if(psummary.iph->ip_p == TCP) {
        connection = (std::string)inet_ntoa(psummary.iph->ip_src) + " " + std::to_string(ntohs(psummary.tcph->th_sport)) + " " + (std::string)inet_ntoa(psummary.iph->ip_dst) + " " + std::to_string(ntohs(psummary.tcph->th_dport));
        connectionReverse = (std::string)inet_ntoa(psummary.iph->ip_dst) + " " + std::to_string(ntohs(psummary.tcph->th_dport)) + " " + (std::string)inet_ntoa(psummary.iph->ip_src) + " " + std::to_string(ntohs(psummary.tcph->th_sport));
      }
      if(psummary.iph->ip_p == UDP) {
        connection = (std::string)inet_ntoa(psummary.iph->ip_src) + " " + std::to_string(ntohs(psummary.udph->uh_sport)) + " " + (std::string)inet_ntoa(psummary.iph->ip_dst) + " " + std::to_string(ntohs(psummary.udph->uh_dport));
        connectionReverse = (std::string)inet_ntoa(psummary.iph->ip_dst) + " " + std::to_string(ntohs(psummary.udph->uh_dport)) +  " " + (std::string)inet_ntoa(psummary.iph->ip_src) + " " + std::to_string(ntohs(psummary.udph->uh_sport));
      }

      //create keys
      std::pair<std::string, std::string> key = make_pair(connection, connectionReverse);
      std::pair<std::string, std::string> revKey = make_pair(connectionReverse, connection);
      //orig to dest
      if(connectionsTable.find(key) != connectionsTable.end()) {
        struct connectInfo currentConnInfo = connectionsTable[key];

        connectInfo.ts = currentConnInfo.ts;
        connectInfo.dur = psummary.ts - currentConnInfo.ts;
        connectInfo.proto = currentConnInfo.proto;
        connectInfo.oToRPkts = currentConnInfo.oToRPkts + 1;
        connectInfo.rToOPkts = currentConnInfo.rToOPkts;
        connectInfo.oToRBytes = currentConnInfo.oToRBytes + psummary.appDataVol;
        connectInfo.rToOBytes = currentConnInfo.rToOBytes;

        connectionsTable[key] = connectInfo;
      }
      //dest to orig
      else if(connectionsTable.find(revKey) != connectionsTable.end()) {
        struct connectInfo currentConnInfo = connectionsTable[revKey];

        connectInfo.ts = currentConnInfo.ts;
        connectInfo.dur = psummary.ts - currentConnInfo.ts;
        connectInfo.proto = currentConnInfo.proto;
        connectInfo.oToRPkts = currentConnInfo.oToRPkts;
        connectInfo.rToOPkts = currentConnInfo.rToOPkts + 1;
        connectInfo.oToRBytes = currentConnInfo.oToRBytes;
        connectInfo.rToOBytes = currentConnInfo.rToOBytes + psummary.appDataVol;

        connectionsTable[revKey] = connectInfo;
      }
      //doesnt exist
      else {
        connectInfo.ts = psummary.ts;
        connectInfo.dur = 0;
        connectInfo.proto = psummary.iph->ip_p;
        connectInfo.oToRPkts = 1;
        connectInfo.rToOPkts = 0;
        connectInfo.oToRBytes = psummary.appDataVol;
        connectInfo.rToOBytes = 0;

        connectionsTable[key] = connectInfo;
      }
    }
    else if(roundTripTimes && next_packet(&psummary)) {
      //make connection
      std::string connection;
      std::string connectionReverse;
      struct roundTripInfo roundTripInfo;
      if(psummary.iph->ip_p == TCP) {
        //create keys
        connection = (std::string)inet_ntoa(psummary.iph->ip_src) + " " + std::to_string(ntohs(psummary.tcph->th_sport)) + " " + (std::string)inet_ntoa(psummary.iph->ip_dst) + " " + std::to_string(ntohs(psummary.tcph->th_dport));
        connectionReverse = (std::string)inet_ntoa(psummary.iph->ip_dst) + " " + std::to_string(ntohs(psummary.tcph->th_dport)) + " " + (std::string)inet_ntoa(psummary.iph->ip_src) + " " + std::to_string(ntohs(psummary.tcph->th_sport));
        std::pair<std::string, std::string> key = make_pair(connection, connectionReverse);
        std::pair<std::string, std::string> revKey = make_pair(connectionReverse, connection);

        //either first data sending packet from src to dest, or destination trying to send info back to src
        if(roundTripTimesTable.find(key) != roundTripTimesTable.end()) {
          struct roundTripInfo currentRoundTripInfo = roundTripTimesTable[key];
          roundTripInfo = currentRoundTripInfo;

          //first data carrying packet already stored, check if r to o ack yet
          if (!roundTripInfo.rToOAck && roundTripInfo.rToOSeq != 0 && roundTripInfo.rToOBytes != 0){
            if(ntohl(psummary.tcph->th_ack) > roundTripInfo.rToOSeq) {
              roundTripInfo.rToOAck = true;
              roundTripInfo.rToORtt = psummary.ts - roundTripInfo.rToOTs;
            }
          }
          //if first data-carrying packet
          if(currentRoundTripInfo.oToRBytes == 0 && psummary.appDataVol != 0) {
            roundTripInfo.oToRSeq = ntohl(psummary.tcph->th_seq);
            roundTripInfo.oToRBytes = psummary.appDataVol;
            roundTripInfo.oToRTs = psummary.ts;
            roundTripInfo.oToRRtt = 0;
          }

          roundTripTimesTable[key] = roundTripInfo;
        }
        //dest to orig
        else if(roundTripTimesTable.find(revKey) != roundTripTimesTable.end()) {
          struct roundTripInfo currentRoundTripInfo = roundTripTimesTable[revKey];
          roundTripInfo = currentRoundTripInfo;

          //if first data-carrying packet already recorded
          if(!roundTripInfo.oToRAck && roundTripInfo.oToRBytes != 0){
            if(ntohl(psummary.tcph->th_ack) > roundTripInfo.oToRSeq) {
              roundTripInfo.oToRAck = true;
              roundTripInfo.oToRRtt = psummary.ts - roundTripInfo.oToRTs;
            }
          }
          if(roundTripInfo.rToOBytes == 0 && psummary.appDataVol != 0) { //new connection or first packet with more than 0 bytes
            roundTripInfo.rToOSeq = ntohl(psummary.tcph->th_seq);
            roundTripInfo.rToOBytes = psummary.appDataVol;
            roundTripInfo.rToOTs = psummary.ts;
            roundTripInfo.rToORtt = 0;
          }

          roundTripTimesTable[revKey] = roundTripInfo;
        }
        //doesnt exist
        else {
          roundTripInfo.oToRSeq = ntohl(psummary.tcph->th_seq);
          roundTripInfo.oToRAck = false;
          roundTripInfo.oToRTs = psummary.ts;
          roundTripInfo.oToRRtt = 0;
          roundTripInfo.oToRBytes = psummary.appDataVol;
          roundTripInfo.rToOSeq = 0;
          roundTripInfo.rToOAck = false;
          roundTripInfo.rToOTs = 0;
          roundTripInfo.rToORtt = 0;
          roundTripInfo.rToOBytes = 0;

          roundTripTimesTable[key] = roundTripInfo;
        }
      }
    }
  }

  if(connSumms) {
    printConnSumms(connectionsTable);
  }
  if(roundTripTimes) {
    printRoundTripTimes(roundTripTimesTable);
  }
}

int main(int argc, char* argv[]) {
  int ch;
  if (argc != 4) { // no arguments were passed
    perror("Incorrect number of arguments");
    exit(0);
  }
  else { //order printed should always be "-i" "-p" "-o"
    while((ch = getopt(argc, argv, "r:pst")) != -1) {
      switch (ch) {
        case 'r':
          traceFile = fopen(optarg, "rb");
          break;
        case 'p':
          pktDump = true;
          break;
        case 's':
          connSumms = true;
          break;
        case 't':
          roundTripTimes = true;
          break;
        case '?':
          perror("unrecognizable command");
          exit(0);
          break;
        default:
          break;
      }
    }
  }

  if(traceFile != NULL) {
    trace();
  }
  else {
    perror("trace file is null");
    exit(0);
  }
}
