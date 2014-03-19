/*
 * University of Wisconsin--Madison CS 642 Information Security
 *
 * scanner.c
 *   A poor attempt at logging SYN packets
 *   This code has both design flaws and bugs in it. 
 *   Your goal is to find them and describe fixes.
 *
 * Compiles using ``gcc -lpcap'' on OS X 10.6.8, 
 * other platforms your mileage will vary
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>


void logpacket( unsigned char* payload, struct ip* ipheader, struct tcphdr* tcpheader )
{
    char reportBuf[16 + ipheader->ip_len];
    unsigned int src, dst;
    int lensofar = 0;
    FILE* fd;
    
    fd = fopen( "log.txt", "a" );

    src = ntohl(ipheader->ip_src.s_addr);
    dst = ntohl(ipheader->ip_dst.s_addr);

    lensofar = snprintf( reportBuf, ipheader->ip_len,  
                "%d.%d.%d.%d,%d.%d.%d.%d,",  
                    (src & 0xFF000000) >> 24, 
                    (src & 0x00FF0000) >> 16,
                    (src & 0x0000FF00) >> 8, 
                    (src & 0x000000FF),
                    (dst & 0xFF000000) >> 24, 
                    (dst & 0x00FF0000) >> 16,
                    (dst & 0x0000FF00) >> 8, 
                    (dst & 0x000000FF) );

    memcpy( reportBuf + lensofar + 1, payload, ipheader->ip_len );  

    fwrite( reportBuf, sizeof(char), 255, fd ); // just write first 255 bytes  
    fwrite( "\n\n\n", sizeof(char), 3, fd ); 

    fclose( fd );
}



int main(int argc, char* argv[] )
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = NULL;
    const unsigned char* packet = NULL;
    struct pcap_pkthdr header;	
    struct ip* ipheader = NULL;
    struct tcphdr* tcpheader = NULL;
    unsigned char* payload = NULL;
    

    if( argc != 2 ) {
        printf( "Error, not enough arguments. Give a pcap file name.\n" ); 
        return 0;
    }

    pcap = pcap_open_offline( argv[1], errbuf );

    while( (packet = pcap_next( pcap, &header ) ) != NULL )
    {
        ipheader = (struct ip*)(packet + 14);  // Look past ethernet header
        tcpheader = (struct tcphdr*)(packet + 14 + ipheader->ip_hl * 4);  // Look past IP header

        if( ipheader->ip_p == 0x06 && tcpheader->th_flags == TH_SYN ) 
        {
            payload = (unsigned char*)(packet + 14 + ipheader->ip_hl * 4 + tcpheader->th_off * 4 ); 
            logpacket( payload, ipheader, tcpheader );
        }
    }


    return 0;
}
