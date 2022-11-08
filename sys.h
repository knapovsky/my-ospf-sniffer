/**
* Projekt do predmetu ISA - OSPFv2, OSPFv3 sniffer s vypsanim databaze
* soubor: 	sys.h
*
* Autor:	Martin Knapovsky
* E-Mail:	xknapo02@stud.vutbr.cz
* Datum:	5.11.2011
*
* Popis souboru: Modul obsahujici funkce pro tisk, prevod a kontrolu
*                ruznych datovych struktur pouzitych v programu.
*/

#ifndef SYS_H_INCLUDED
#define SYS_H_INCLUDED

#include"const.h"
#include<netinet/in.h>
#include<arpa/inet.h>
#include<netinet/ip6.h>
#include<netinet/ip.h>
//#include<netinet/ether.h>
#include<net/ethernet.h>

#define APP_NAME		"myospfsniffer"
#define APP_DESC		"Assignment for ISA - VUT FIT Brno"
#define APP_COPYRIGHT	"Copyright (c) 2011 Knapovsky Martin"
#define APP_DISCLAIMER	"THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM."

// Tiskne napovedu
void print_help();

// Tiskne 8bitove cislo v binarni reprezentaci na STDOUT
void print_short_bit(u_int8_t );

// Tiskne Ethernetovou hlavicku
void print_ethernet(const struct ether_header* );

// Tiskne IPv4 Hlavicku
void print_ipv4(const struct ip* );

// Tiskne IPv6 adresu v plnem formatu
void ipv6_to_str_unexpanded(char * , const struct in6_addr * );

// Kontroluje, zda je cilova adresa broadcast adresou OSPFv3
int check_ipv6_ospf_dst(const struct in6_addr* );

// Tiskne IPv4 adresu v plnem formatu
// pouziva bitove posuvy
void ipv4_to_str(char * , u_int32_t );

// Tiskne prefix v plnem formatu - delka podle delky obsazene v packetu resp. LSA Hlavicce
void print_address_prefix(char* , int );

// Tiskne IPv6 Hlavicku
void print_ipv6(const struct ip6_hdr* );

#endif
