/*
*Timothy Kuo
*tyk3
*proj2.cpp
*Created on 1/27/17
*This file completes a packet trace of an input trace file.  It con do different things based on
*the command that is given.  The possible commands are: -s, -e, -i, -t, -m that do the following
*respectively: prints a four-line trace summary, dumps info from Ether headers, dumps info from
*IP headers, counts packet types, and produces a traffic matrix of the file.
*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <string>
#include <map>
#include <set>

#define SRC_ADDR_LENGTH 6
#define DST_ADDR_LENGTH 6
#define fullEthrHdrLength 14
#define fullIPHdrLength 34
#define IP 2048
#define numEleRead 1
#define TCP 6
#define UDP 17

FILE* traceFile = NULL;
bool traceSummary = false;
bool dumpEtherHdrs = false;
bool dumpIPHdrs = false;
bool countPktTypes = false;
bool produceTrafficMatrix = false;

struct pktinfo {
    unsigned int sec, usec;
    unsigned short caplen, ignored;
};

struct trafficinfo {
  int numpkts;
  unsigned long datavol;
};

void printTraceSummary(int totNumPkts, double timestampFirstPkt, double timestampCurPkt) {
  printf("PACKETS: %d\n", totNumPkts);
  printf("FIRST: %.6f\n", timestampFirstPkt);
  printf("LAST: %.6f\n", timestampCurPkt);
  printf("DURATION: %.6f\n", timestampCurPkt - timestampFirstPkt);
}

void printEtherHdrs(double timestampCurPkt, unsigned char srcAddr[], unsigned char dstAddr[], unsigned short type, unsigned short caplen) {
  //print time
  printf("%.6f", timestampCurPkt);
  if(caplen < fullEthrHdrLength) {
    printf(" Ethernet-truncated\n");
  }
  else {
    printf(" ");
    for(int i = 0; i < DST_ADDR_LENGTH; i++) {
      printf("%02x", dstAddr[i]);
      if(i != 5) {
        printf(":");
      }
    }
    printf(" ");
    for(int i = 0; i < SRC_ADDR_LENGTH; i++) {
      printf("%02x", srcAddr[i]);
      if(i != 5) {
        printf(":");
      }
    }
    printf(" 0x%04x\n", type);
  }
}

void printIPHdrs(double timestamp, unsigned short caplen, unsigned short type) {
  printf("%.6f", timestamp);
  //print everything
  if(caplen < fullEthrHdrLength) {
    printf(" unknown\n");
    fseek(traceFile, caplen, SEEK_CUR);
  }
  else {
    //non-IP packet
    if(type != IP) {
      printf(" non-IP\n");
      fseek(traceFile, caplen-fullEthrHdrLength, SEEK_CUR);
    }
    //IP packet
    else {
      //contains fixed ip header length
      if(caplen >= fullIPHdrLength) {
        struct ip ipInfo;
        fread(&ipInfo, sizeof(ipInfo), 1, traceFile);
        //ip not truncated
        if(caplen - fullEthrHdrLength >= ipInfo.ip_hl*4) {
          printf(" %s", inet_ntoa(ipInfo.ip_src));
          printf(" %s", inet_ntoa(ipInfo.ip_dst));
          printf(" %u", (ipInfo.ip_hl)*4);
          printf(" %d", ipInfo.ip_p);
          printf(" %d\n", ipInfo.ip_ttl);
          fseek(traceFile, caplen-fullEthrHdrLength-sizeof(ipInfo), SEEK_CUR);
        }
        //ip truncated
        else {
          printf(" IP-truncated\n");
          fseek(traceFile, caplen-fullEthrHdrLength-sizeof(ipInfo), SEEK_CUR);
        }
      }
      //shorter than minimum ip header length
      else {
        printf(" IP-truncated\n");
        fseek(traceFile, caplen-fullEthrHdrLength, SEEK_CUR);
      }
    }
  }
}

void processIPHdrs(unsigned short caplen, double timestampCurPkt, unsigned short type) {
  if (caplen < fullEthrHdrLength) {
    printIPHdrs(timestampCurPkt, caplen, ntohs(type));
  }
  else {
    //read the ether header
    fseek(traceFile, SRC_ADDR_LENGTH, SEEK_CUR);
    fseek(traceFile, DST_ADDR_LENGTH, SEEK_CUR);
    if(numEleRead != fread(&type, sizeof(type), 1, traceFile)) {
      perror("type not read correctly");
    }

    printIPHdrs(timestampCurPkt, caplen, ntohs(type));
  }
}

void printPktTypes(int numEthFullPkts, int numEthPartialPkts, int numNonIP,
  int numIPFullPkts, int numIPPartialPkts, std::set<std::string> uniqueSrcs,
  std::set<std::string> uniqueDsts, int numTCP, int numUDP, int numOther) {
    printf("ETH: %d %d\n", numEthFullPkts, numEthPartialPkts);
    printf("NON-IP: %d\n", numNonIP);
    printf("IP: %d %d\n", numIPFullPkts, numIPPartialPkts);
    printf("SRC: %lu\n", uniqueSrcs.size());
    printf("DST: %lu\n", uniqueDsts.size());
    printf("TRANSPORT: %d %d %d\n", numTCP, numUDP, numOther);
}

void printTrafficMatrix(std::map<std::string, trafficinfo> trafficInfo) {
  std::map<std::string, trafficinfo>::iterator it;
  for (it = trafficInfo.begin(); it != trafficInfo.end(); it++ ) {
    printf("%s %d %lu\n", it->first.c_str(), it->second.numpkts, it->second.datavol);
  }
}

int processTraceSummary(int totNumPkts, unsigned short caplen) {
  fseek(traceFile, caplen, SEEK_CUR);
  return totNumPkts + 1;
}

void trace() {
  //12 bytes of meta info in each packet
  struct pktinfo meta;
  //tot num pkts for -s command
  int totNumPkts = 0;
  //timestamps of packets
  double timestampFirstPkt = 0.0;
  double timestampCurPkt = 0.0;
  //packet type in ether header
  unsigned short type = -1;
  //return variables for -t command
  int numEthFullPkts = 0;
  int numEthPartialPkts = 0;
  int numNonIP = 0;
  int numIPFullPkts = 0;
  int numIPPartialPkts = 0;
  int numTCP = 0;
  int numUDP = 0;
  int numOther = 0;
  std::set<std::string> uniqueSrcs;
  std::set<std::string> uniqueDsts;
  //return variable for -m command
  std::map<std::string, trafficinfo> trafficInfo;
  //while succesfully read meta info
  while(numEleRead == fread (&meta, sizeof(meta), 1, traceFile)) {
    //record current time
    meta.sec = ntohl(meta.sec);
    meta.usec = (ntohl(meta.usec)/1000000.0);

    unsigned short caplen = ntohs(meta.caplen);

    if(traceSummary) {
      totNumPkts = processTraceSummary(totNumPkts, caplen);
      //record first timestamp
      if(totNumPkts == 1) {
        timestampFirstPkt = timestampCurPkt;
      }
    }
    else if(dumpEtherHdrs) {
      unsigned char srcAddr[SRC_ADDR_LENGTH];
      unsigned char dstAddr[DST_ADDR_LENGTH];
      //if contains full Eternet frame header
      if(caplen >= fullEthrHdrLength) {
        //read the ether header
        if(numEleRead != fread(&srcAddr, SRC_ADDR_LENGTH, 1, traceFile)) {
          perror("src address not read");
        }
        if(numEleRead != fread(&dstAddr, DST_ADDR_LENGTH, 1, traceFile)) {
          perror("dst address not read");
        }
        if(numEleRead != fread(&type, sizeof(type), 1, traceFile)) {
          perror("type not read");
        }

        printEtherHdrs(timestampCurPkt, srcAddr, dstAddr, ntohs(type), caplen);
        //skip past the rest of the packet
        fseek(traceFile, caplen-fullEthrHdrLength, SEEK_CUR);
      }
      else {
        printEtherHdrs(timestampCurPkt, srcAddr, dstAddr, ntohs(type), caplen);
        //skip past length of caplen
        fseek(traceFile, caplen, SEEK_CUR);
      }
    }
    else if(dumpIPHdrs) {
      processIPHdrs(caplen, timestampCurPkt, ntohs(type));
    }
    else if(countPktTypes) {
      //check ether hdr length
      if(caplen >= fullEthrHdrLength) {
        numEthFullPkts++;
        fseek(traceFile, SRC_ADDR_LENGTH, SEEK_CUR);
        fseek(traceFile, DST_ADDR_LENGTH, SEEK_CUR);
        fread(&type, sizeof(type), 1, traceFile);
        //check if nonIP
        if(ntohs(type) != IP) {
          numNonIP++;
        }
        //check ip hdr length
        if(caplen < fullIPHdrLength) {
          //if it's an IP packet
          if(ntohs(type) == IP) {
            numIPPartialPkts++;
          }
          fseek(traceFile, caplen-fullEthrHdrLength, SEEK_CUR);
        }
        else {
          struct ip ipInfo;
          //store dst and src addresses
          fread(&ipInfo, sizeof(ipInfo), 1, traceFile);
          if(caplen - fullEthrHdrLength >= ipInfo.ip_hl*4) {
            numIPFullPkts++;
            std::string src = inet_ntoa(ipInfo.ip_src);
            std::string dst = inet_ntoa(ipInfo.ip_dst);
            uniqueSrcs.insert(src);
            uniqueDsts.insert(dst);

            //store protocols
            if(ipInfo.ip_p == TCP) {
              numTCP++;
            }
            else if(ipInfo.ip_p == UDP) {
              numUDP++;
            }
            else {
              numOther++;
            }
          }
          else {
            numIPPartialPkts++;
          }

          fseek(traceFile, caplen-fullEthrHdrLength-sizeof(ipInfo), SEEK_CUR);
        }
      }
      else {
        numEthPartialPkts++;
        fseek(traceFile, caplen, SEEK_CUR);
      }
    }
    else if(produceTrafficMatrix) {
      if(caplen >= fullIPHdrLength) {
        fseek(traceFile, SRC_ADDR_LENGTH, SEEK_CUR);
        fseek(traceFile, DST_ADDR_LENGTH, SEEK_CUR);
        fread(&type, sizeof(type), 1, traceFile);

        if(ntohs(type) == IP) {
          struct ip ipInfo;
          fread(&ipInfo, sizeof(ipInfo), 1, traceFile);
          std::string addrses = (std::string)inet_ntoa(ipInfo.ip_src) + " " + (std::string)inet_ntoa(ipInfo.ip_dst);
          if(trafficInfo.find(addrses) == trafficInfo.end()) {
            trafficinfo tInfo;
            tInfo.numpkts = 1;
            tInfo.datavol = ntohs(ipInfo.ip_len);
            trafficInfo[addrses] = tInfo;
          }
          else {
            trafficinfo tInfo;
            tInfo.numpkts = trafficInfo[addrses].numpkts + 1;
            tInfo.datavol = trafficInfo[addrses].datavol + ntohs(ipInfo.ip_len);
            trafficInfo[addrses] = tInfo;
          }
          fseek(traceFile, caplen-fullEthrHdrLength-sizeof(ipInfo), SEEK_CUR);
        }
      }
      else {
        fseek(traceFile, caplen, SEEK_CUR);
      }
    }
  }

  if(traceSummary) {
    printTraceSummary(totNumPkts, timestampFirstPkt, timestampCurPkt);
  }
  if(countPktTypes) {
    printPktTypes(numEthFullPkts, numEthPartialPkts, numNonIP, numIPFullPkts,
      numIPPartialPkts, uniqueSrcs, uniqueDsts, numTCP, numUDP, numOther);
  }
  if(produceTrafficMatrix) {
    printTrafficMatrix(trafficInfo);
  }
}

int main(int argc, char* argv[]) {
  int ch;
  if (argc < 2) { // no arguments were passed
    perror("Not enough arguments");
  }
  else if(argc > 4) {
    perror("Too many command line arguments");
  }
  else { //order printed should always be "-i" "-p" "-o"
    while((ch = getopt(argc, argv, "r:seitm")) != -1) {
      switch (ch) {
        case 'r':
          traceFile = fopen(optarg, "rb");
          break;
        case 's':
          traceSummary = true;
          break;
        case 'e':
          dumpEtherHdrs = true;
          break;
        case 'i':
          dumpIPHdrs = true;
          break;
        case 't':
          countPktTypes = true;
          break;
        case 'm':
          produceTrafficMatrix = true;
          break;
        case '?':
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
  }
}
