/**
* Projekt do predmetu ISA - OSPFv2, OSPFv3 sniffer s vypsanim databaze
* soubor: 	ospfv3_db.h
*
* Autor:	Martin Knapovsky
* E-Mail:	xknapo02@stud.vutbr.cz
* Datum:	5.11.2011
*
* Popis souboru: Modul obsahujici struktury a funkce pro vypis
*                OSPFv3 Topologie podle prijatych packetu.
*/



#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> // getopt
#include <pcap.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/ip.h>
//#include <netinet/ether.h>
#include <net/ethernet.h>
#include "ospfv3.h"

struct ospf3_db_item{

    struct ospf3_lsa* lsa;
    struct ospf3_db_item* next;

} ospf3_db_item;

struct ospf3_db_area{

    // area id
    u_int32_t area_id;
    // Router LSA Database Item
    struct ospf3_db_item* rtr_ls;
    // Network LSA Database Item
    struct ospf3_db_item* net_ls;
    // Inter-Area Prefix LSA Database Item
    struct ospf3_db_item* ia_p_ls;
    // Inter-Area Router LSA
    struct ospf3_db_item* ia_rtr_ls;
    // AS-External LSA
    struct ospf3_db_item* asext_ls;
    // Link LSA Database Item
    struct ospf3_db_item* link_ls;
    // Intra-Area Prefix LSA
    struct ospf3_db_item* intra_p_ls;
    // ukazatel na dalsi prvek seznamu
    struct ospf3_db_area* next;

} ospf3_db_area;

// struktura OSPFv3 databaze instanci
struct ospf3_db_instance{

    // instance id
    u_int32_t instance_id;
    // ukazatel na seznam "area"
    struct ospf3_db_area* area_list;
    // next instance id
    struct ospf3_db_instance* next;

} ospf3_db_instance;

// databaze obsahujici OSPFv3 LSA Topologicke informace
struct ospf3_db {

    // id routeru
    u_int32_t router_id;
    // seznam instanci OSPFv3 na danem routeru
    struct ospf3_db_instance* instance_list;
    // ukazatel na dalsi databazi
    struct ospf3_db* next;

} ospf3_db;

// Inicializuje OSPFv3 Databazi
void ospf3_db_init(struct ospf3_db* );

// Pridava novou databazi
struct ospf3_db* ospf3_db_add_db (struct ospf3_db* );

// Pridava polozku do databaze
struct ospf3_db_item* ospf3_db_add_item (struct ospf3_db_item*, struct ospf3_lsa* );

// Tiskne dane polozky z databaze
void print_ospf3_db_item (const struct ospf3_db_item* );

// Tiskne OSPFv3 LSA Databazi
void print_ospf3_db (struct ospf3_db* );

// Rusi dane polozky databaze v pameti
int free_ospf3_db_item (struct ospf3_db_item* );

// Rusi danou databazi
int free_ospf3_db (struct ospf3_db* );

// Kopiruje LSA do databaze
struct ospf3_lsa* ospf3_db_add_lsa_to_item(struct ospf3_lsa* );

// Pridava LSA do databaze
struct ospf3_db* ospf3_db_add_lsa_to_db (struct ospf3_db* , struct ospf3_lsa*, u_int32_t, u_int32_t, u_int32_t);
