/**
* Projekt do predmetu ISA - OSPFv2, OSPFv3 sniffer s vypsanim databaze
* soubor: 	main.h
*
* Autor:	Martin Knapovsky
* E-Mail:	xknapo02@stud.vutbr.cz
* Datum:	5.11.2011
*
* Popis:	Program ke sve praci pouziva socket API. Jako parametr
*          prijme nazev rozhranni, na kterem ma naslouchat
*          v promiskuitnim rezimu a vypisuje informace
*          o prijatem OSPF packetu.
*
* Pouziti:	./myospfsniffer [-i=%interface_name%]
*          %interface_name% - jmeno rozhranni
*          pozn. pokud neni jmeno rozhranni zadano, pokusi se program
*          otevrit vychozi rozranni
*
*/

#ifndef MAIN_H_INCLUDED
#define MAIN_H_INCLUDED

#include <netinet/in.h>

// Vyraz pro filtrovani vstupu
#define FILTER_EXP ""
#define FILTER_EXP1 "(ip host 224.0.0.5) or (ip host 224.0.0.6) or (ip6 host ff02::5) or (ip6 host ff02::6)"

/** Funkce je volana, pokud je odposlechnut packet. Packet je dale zpracovan podle typu
*   IP protokolu a OSPF verze. Informace jsou tisknuty na STDOUT.
*@const u_char *packet - ukazatel na zacatek packetu
*/
void got_packet(u_char* , const struct pcap_pkthdr* , const u_char* );

#endif // MAIN_H_INCLUDED
