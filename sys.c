/**
* Projekt do predmetu ISA - OSPFv2, OSPFv3 sniffer s vypsanim databaze
* soubor: 	sys.c
*
* Autor:	Martin Knapovsky
* E-Mail:	xknapo02@stud.vutbr.cz
* Datum:	5.11.2011
*
* Popis souboru: Modul obsahujici funkce pro tisk, prevod a kontrolu
*                ruznych datovych struktur pouzitych v programu.
*/

#include "sys.h"
#include "const.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>

#ifdef _LINUX_SOURCE
	#include <netinet/ether.h>
#endif

// Tiskne napovedu
void print_help(){
    // about
    printf("%s - %s\n", APP_NAME, APP_DESC);
	printf("%s\n", APP_COPYRIGHT);
	printf("%s\n", APP_DISCLAIMER);
	printf("\n");

    // pouziti
	printf("Usage: %s -i [interface]\n", APP_NAME);
	printf("\n");
	printf("Options:\n");
	printf("    interface    Listen on <interface> for packets.\n");
	printf("\n");
}

// Tiskne 8bitove cislo v binarni reprezentaci na STDOUT
void print_short_bit(u_int8_t number){

    u_int8_t msb = 128;
    int i;

    for(i = 0; i < 8; i++){
        if(number & msb){
            printf("1");
        }
        else printf("0");

        // bitovy posuv
        number = number << 1;
    }
}

// Tiskne Ethernetovou hlavicku
void print_ethernet(const struct ether_header* ethernet){

    printf("%s---Ethernet Header---\n", ETHERNET_FORMAT);
    printf("%sDestination      : %s\n", ETHERNET_FORMAT, (char*)ether_ntoa((struct ether_addr* )ethernet->ether_dhost));
    printf("%sSource           : %s\n", ETHERNET_FORMAT,(char*)ether_ntoa((struct ether_addr*)ethernet->ether_shost));
    printf("%sType             : ", ETHERNET_FORMAT);
    switch(ethernet->ether_type){
        case IPV4: printf("IPv4");
                   break;
        case IPV6: printf("IPv6");
                   break;
    }
    printf("\n\n");

    return;
}

// Tiskne IPv4 Hlavicku
void print_ipv4(const struct ip* ipv4){

    printf("%s---IPv4 Header---\n", IP_FORMAT);
    printf("%sVersion          : %d \n", IP_FORMAT, ipv4->ip_v);
    printf("%sIP Header Length : %d \n", IP_FORMAT, ipv4->ip_hl * 4);
    printf("%sType of Service  : 0x%X \n", IP_FORMAT, ipv4->ip_tos);
    printf("%sTotal Length     : %d \n", IP_FORMAT, ntohs(ipv4->ip_len));
    printf("%sIdentification   : %d \n", IP_FORMAT, ntohs(ipv4->ip_id));
    printf("%sRF Flag          : %d \n", IP_FORMAT, (ipv4->ip_off & 0x8000) >> 12);
    printf("%sDF Flag          : %d \n", IP_FORMAT, (ipv4->ip_off & 0x4000) >> 12);
    printf("%sMF Flag          : %d \n", IP_FORMAT, (ipv4->ip_off & 0x2000) >> 12);
    printf("%sOffset           : %d \n", IP_FORMAT, (ipv4->ip_off & 0x1fff));
    printf("%sTTL              : %d \n", IP_FORMAT, ipv4->ip_ttl);
    printf("%sProtocol         : %d \n", IP_FORMAT, ipv4->ip_p);
    printf("%sCheck Sum        : 0x%X \n", IP_FORMAT, ntohs(ipv4->ip_sum));
    printf("%sSource IP Addr   : %s \n", IP_FORMAT, inet_ntoa(ipv4->ip_src));
    printf("%sDest IP Addr     : %s \n", IP_FORMAT, inet_ntoa(ipv4->ip_dst));
    printf("\n");

    return;
}

// Tiskne IPv6 adresu v plnem formatu
void ipv6_to_str_unexpanded(char * str, const struct in6_addr * addr) {
    
    #ifdef IP_PRETTY_PRINT
        inet_ntop(AF_INET6, addr, str, INET6_ADDRSTRLEN);
    #endif
    #ifndef IP_PRETTY_PRINT
        sprintf(str, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                    (int)addr->s6_addr[0], (int)addr->s6_addr[1],
                    (int)addr->s6_addr[2], (int)addr->s6_addr[3],
                    (int)addr->s6_addr[4], (int)addr->s6_addr[5],
                    (int)addr->s6_addr[6], (int)addr->s6_addr[7],
                    (int)addr->s6_addr[8], (int)addr->s6_addr[9],
                    (int)addr->s6_addr[10], (int)addr->s6_addr[11],
                    (int)addr->s6_addr[12], (int)addr->s6_addr[13],
                    (int)addr->s6_addr[14], (int)addr->s6_addr[15]);
    #endif
}

// Kontroluje, zda je cilova adresa broadcast adresou OSPFv3
int check_ipv6_ospf_dst(const struct in6_addr* addr){

    // prvni bajty
    if(((int)addr->s6_addr[0] == 0xff) && ((int)addr->s6_addr[1] == 0x02)){

        int i;
        // bajty 2 - 14
        for(i = 2; i < 15; i++){
            if((i < 14) && ((int)addr->s6_addr[i] != 0x00)) return 0;
        }
        // posledni bajt
        if(((int)addr->s6_addr[15] == 0x05 || (int)addr->s6_addr[15] == 0x06)) {return 1;}
    }

    return 0;
}

// Tiskne IPv4 adresu v plnem formatu
// pouziva bitove posuvy
void ipv4_to_str(char * str, u_int32_t ip){
    
    #ifdef IP_PRETTY_PRINT
        u_int32_t ip_reverse = ntohl(ip);
        inet_ntop(AF_INET, (struct in_addr*)(&(ip_reverse)), str, INET_ADDRSTRLEN);
    #endif
    #ifndef IP_PRETTY_PRINT
        sprintf(str, "%03d.%03d.%03d.%03d", ip >> 24 & 0x000000ff, ip >> 16 & 0x000000ff, ip >> 8 & 0x000000ff, ip & 0x000000ff);
    #endif
    return;

}

// Tiskne prefix v plnem formatu - delka podle delky obsazene v packetu resp. LSA Hlavicce
void print_address_prefix(char* pointer, int length){
    
    #ifdef IP_PRETTY_PRINT
        // pole znaku pro ulozeni prefixu
        char prefix_string[INET6_ADDRSTRLEN];
        // alokace prostoru pro prefix
        struct in6_addr* prefix = (struct in6_addr*)(malloc(sizeof(struct in6_addr)));
        // vynulovani alokovane struktury
        memset(prefix, 0x00, sizeof(struct in6_addr));
        // nakopirovani prefixu
        memcpy(prefix, (struct in6_addr*)pointer, (length%8 > 0)?(length/8 + 1):(length/8));
        // prevod prefixu do retezce
        inet_ntop(AF_INET6, prefix, prefix_string, INET6_ADDRSTRLEN);
        // tisk adresy
        printf("%s", prefix_string);
        // uvolneni pameti
        free(prefix);
    #endif
    #ifndef IP_PRETTY_PRINT
        int i;
        for(i = 0; i < length/8 ; i++){
            // Po kazdych 2 bajtech tiskne :
            if( (i > 0) && (i % 2 == 0) ) printf(":");
            // MSB
            printf("%X", (pointer[i] & 0xf0) >> 4);
            // LSB
            printf("%X", pointer[i] & 0x0f);
        }
    #endif

    return;
}

// Tiskne IPv6 Hlavicku
void print_ipv6(const struct ip6_hdr* ipv6){

    // Pole pro uchovani prevedenych adres
    char source[INET6_ADDRSTRLEN];
    char dest[INET6_ADDRSTRLEN];
    ipv6_to_str_unexpanded(source, &(ipv6->ip6_src));
    ipv6_to_str_unexpanded(dest, &(ipv6->ip6_dst));

    printf("%s---IPv6 Header---\n", IP_FORMAT);
    printf("%sVersion          : 0x%X \n", IP_FORMAT, (ipv6->ip6_vfc & 0xf0)>>4);
    printf("%sTraffic Class    : 0x%X \n", IP_FORMAT, (ipv6->ip6_vfc & 0x0f));
    printf("%sFlow ID          : %d \n", IP_FORMAT, ntohl(ipv6->ip6_flow) & 0x000fffff);
    printf("%sPayload Length   : %d \n", IP_FORMAT, ntohs(ipv6->ip6_plen));
    printf("%sNext Header      : %d \n", IP_FORMAT, ipv6->ip6_nxt);
    printf("%sHop Limit        : %d \n", IP_FORMAT, ipv6->ip6_hlim);
    printf("%sSource IP Addr   : %s \n", IP_FORMAT, source);
    printf("%sDest IP Addr     : %s \n", IP_FORMAT, dest);
    printf("\n");

    return;
}
