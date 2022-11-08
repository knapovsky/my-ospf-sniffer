/**
* Projekt do predmetu ISA - OSPFv2, OSPFv3 sniffer s vypsanim databaze
* soubor: 	const.h
*
* Autor:	Martin Knapovsky
* E-Mail:	xknapo02@stud.vutbr.cz
* Datum:	5.11.2011
*
* Popis souboru: Modul obsahujici definice konstant pouzivanych v programu.
*/

#ifndef CONST_H_INCLUDED
#define CONST_H_INCLUDED


// Nastaveni programu

// _BSD_SOURCE
// dulezite pro spravny preklad
// nastavuje se pri prekladu v Makefile
//#define _BSD_SOURCE 1

#define IP_PRETTY_PRINT
//#define PRINT_LLS
//#define DEBUG
#define PRINT_IP
#define PRINT_ETHERNET
#define PRINT_PACKET_NUMBER
#define PRINT_OSPF_NUMBER
#define PRINTINFO
#define INFO
#define ERROUT stdout
#define ERRDEV 2

// FORMATOVANI VYSTUPU
#define ETHERNET_FORMAT " "
#define IP_FORMAT "  "
#define OSPF_HEADER_FORMAT "   "
#define OSPF_TYPE_FORMAT "    "
#define OSPF_LSA_HEADER_FORMAT "     "
#define OSPF_LSA_FORMAT "      "

// konec nastaveni programu - ostatni definice nemenit

#define IPV4 0x8                    // ethernet type = IPv4
#define IPV6 0xdd86                 // ethernet type = IPv6

#define NUMPACKETS 0

#define MYIP_VHL_HL(vhl)  (((vhl)->ip_vhl) & 0x0f)
#define MYIP_V(ip)        (((ip)->ip_vhl) >> 4)

#define SNAP_LEN 1518               // maximalni pocet odposlechnutych bajtu na packet
#define SIZE_ETHERNET 14            // delka ethernetove hlavicky
//#define ETHER_ADDR_LEN	6       // delka ethernetove adresy
#define SIZE_IPV6 40                // velikost ipv6 hlavicky
#define OSPF2HEADER_LENGTH 24       // velikost OSPFv2 hlavicky

#define BUFFER_LENGTH 20            // velikost bufferu pro prevod ipv4 adresy na string
#define OSPF2HELLOHEADER_LENGTH 20
#define LSA_HEADER_LENGTH 20

#define LSA_TYPE_ROUTER         1
#define LSA_TYPE_NETWORK        2
#define LSA_TYPE_SUM_NETWORK    3
#define LSA_TYPE_SUM_ROUTER     4
#define LSA_TYPE_EXTERNAL       5

#define LINK_TYPE_POINTTOPOINT  1
#define LINK_TYPE_TRANSIT_NET   2
#define LINK_TYPE_STUB_NET      3
#define LINK_TYPE_VIRTUAL       4

#define OSPF_RTR_B      0x01
#define OSPF_RTR_E      0x02
#define OSPF_RTR_V      0x04

// definice pro preklad na BSD systemech
// _BSD_SOURCE definovano - preklad na BSD
// _BSD_SOURCE nedefinovano - preklad na Linuxu
#ifdef _BSD_SOURCE
    #define u_int32_t uint32_t
    #define u_int16_t uint16_t
    #define u_int8_t uint8_t
    #define u_char unsigned char
    #define u_int unsigned int
    #define u_short unsigned short int
#endif


#endif // CONST_H_INCLUDED
