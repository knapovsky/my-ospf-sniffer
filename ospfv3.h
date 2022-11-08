/**
* Projekt do predmetu ISA - OSPFv2, OSPFv3 sniffer s vypsanim databaze
* soubor: 	ospfv3.h
*
* Autor:	Martin Knapovsky
* E-Mail:	xknapo02@stud.vutbr.cz
* Datum:	5.11.2011
*
* Popis souboru: Modul obsahujici struktury a funkce pro vypis OSPFv3
*                packetu.
*/

#ifndef OSPFV3_H_INCLUDED
#define OSPFV3_H_INCLUDED

#include <netinet/in.h>

#define SIZE_OSPF3_HEADER 16
#define ROUTER_LSA  0x2001
#define NETWORK_LSA 0x2002
#define IA_PREFIX_LSA 0x2003
#define IA_RTR_LSA  0x2004
#define ASEXT_LSA   0x4005
#define LINK_LSA    0x0008
#define INTRA_AREA_PREFIX_LSA 0x2009

typedef struct ospf3_header{

    u_int8_t  version;
    u_int8_t  type;
    u_int16_t length;
    u_int32_t router_id;
    u_int32_t area_id;
    u_int16_t checksum;
    u_int8_t instance_id;
    u_int8_t  dummy;

} ospf3_header;

typedef struct ospf3_hello{

    u_int32_t   interface_id;
    u_int32_t   opts;
    u_int16_t   hello_interval;
    u_int16_t   rtr_dead_interval;
    u_int32_t   d_rtr;
    u_int32_t   bd_rtr;
    u_int32_t   neighbor_id;

} ospf3_hello;

#define HELLO_PRIORITY_MASK 0xff000000
#define HELLO_OPTIONS_MASK  0x00ffffff

// type 2
typedef struct ospf3_db_dscrp_hdr{

    u_int32_t   opts;
    u_int16_t   iface_mtu;
    u_int8_t    dummy;
    u_int8_t    bits;
    u_int32_t   dd_seq_num;

} ospf3_db_dscrp_hdr;

#define DB_OPTIONS_MASK 0x00ffffff

// type 3
typedef struct ospf3_ls_req_hdr{

    u_int16_t   dummy;
    u_int16_t   type;
    u_int32_t   ls_id;
    u_int32_t   adv_rtr;

} ospf3_ls_req_hdr;

// type 4
typedef struct ospf3_ls_upd_hdr {

    u_int32_t   num_lsa;

} ospf3_ls_upd_hdr;

// LS ACK ma pouze obecnou hlavicku OSPFv3 nasledujici LSA packety

// Link State Packety OSPF3
#define OSPF3_LSA_HEADER_SIZE   20

// LSA Header structure
typedef struct ospf3_lsa_hdr {

	u_int16_t		age;
	u_int16_t       type;
	u_int32_t		ls_id;
	u_int32_t		adv_rtr;
	u_int32_t		seq_num;
	u_int16_t		ls_chksum;
	u_int16_t		len;

} ospf3_lsa_hdr;

// Router-LSA header
typedef struct ospf3_lsa_rtr_hdr {

    u_int32_t       opts;

} ospf3_lsa_rtr_hdr;

// Router-LSA
typedef struct ospf3_lsa_rtr {

    u_int8_t        type;
    u_int8_t        dummy;
    u_int16_t       metric;
    u_int32_t       if_id;
    u_int32_t       n_if_id;
    u_int32_t       n_rtr_id;

} ospf3_lsa_rtr;

// Network-LSA Header
typedef struct ospf3_lsa_net_hdr {

    u_int32_t       opts;

} ospf3_lsa_net_hdr;

// Network-LSA
typedef struct ospf3_lsa_net {

    u_int32_t       att_rtr;

} ospf3_lsa_net;

// Inter-Area-Prefix-LSA
typedef struct ospf3_lsa_inter_area_prefix_hdr {

    u_int32_t       metric;
    u_int8_t        p_len;
    u_int8_t        p_opts;
    u_int16_t       dummy;

} ospf3_inter_area_prefix_hdr;

// Inter-Area-Router-LSA
typedef struct ospf3_lsa_inter_area_rtr {

    u_int32_t       opts;
    u_int32_t       metric;
    u_int32_t       dst_rtr_id;

} ospf3_lsa_inter_area_rtr;

// AS-External-LSA
typedef struct ospf3_lsa_asext_hdr {

    u_int32_t       metric;
    u_int8_t        p_len;
    u_int8_t        p_opts;
    u_int16_t       ref_ls;

} ospf3_lsa_asext_hdr;

// Link-LSA Header
typedef struct ospf3_lsa_link_hdr {

    u_int32_t       opts;
    struct in6_addr addr;
    u_int32_t       num_pref;

} ospf3_lsa_link_hdr;

// Link-LSA
typedef struct ospf3_lsa_link {

    u_int8_t        p_len;
    u_int8_t        p_opts;
    u_int16_t       dummy;
    // nasleduje prefix, ktery ma vsak promennou
    // delku podle p_len
} ospf3_lsa_link;

// Intra-Area-Prefix Header LSA
typedef struct ospf3_lsa_intra_area_prefix_hdr{

    u_int16_t       num_pref;
    u_int16_t       type;
    u_int32_t       ref_ls_id;
    u_int32_t       ref_adv_rtr;

} ospf3_lsa_intra_area_prefix_hdr;

// Intra-Area-Prefix LSA
typedef struct ospf3_lsa_intra_area_prefix {

    u_int8_t        p_len;
    u_int8_t        p_opts;
    u_int16_t       metric;
    // nasleduje prefix, ktery ma vsak promennou
    // delku podle p_len

} ospf3_lsa_intra_area_prefix;

// OSPF3 LSA
typedef struct ospf3_lsa {

    struct ospf3_lsa_hdr        hdr;
    union{
        struct ospf3_lsa_rtr_hdr    rtr_hdr; // jak se to tam zobrazuje hdr+rtr?
        struct ospf3_lsa_net    net;
        struct ospf3_lsa_inter_area_prefix_hdr  ia_p_hdr;
        struct ospf3_lsa_inter_area_rtr         ia_rtr;
        struct ospf3_lsa_asext_hdr              asext_hdr;
        struct ospf3_lsa_link_hdr               link_hdr;
        struct ospf3_lsa_intra_area_prefix_hdr  intra_p_hdr;
    } data;

} ospf3_lsa;

// Tiskne hlavicku OSPFv3
void print_ospf3_header(const struct ospf3_header* );

// Tiskne OSPFv3 Hello cast packetu
void print_ospf3_hello(const struct ospf3_hello*, int );

// Tiskne OSPFv3 Database Description cast packetu
void print_ospf3_db_dscrp_hdr(const struct ospf3_db_dscrp_hdr* );

// Tiskne OSPFv3 LSA Request cast packetu
void print_ospf3_ls_req_hdr(const struct ospf3_ls_req_hdr* );

// Tiskne OSPFv3 LSA Update cast packetu
void print_ospf3_ls_upd_hdr(const struct ospf3_ls_upd_hdr* );

// Tiskne OSPFv3 LSA Header
void print_ospf3_lsa_hdr(const struct ospf3_lsa_hdr* );

// Tiskne OSPFv3 LSA Router Header cast packetu
void print_ospf3_lsa_rtr_hdr(const struct ospf3_lsa_rtr_hdr* );

// Tiskne OSPFv3 LSA Router cast packetu
void print_ospf3_lsa_rtr(const struct ospf3_lsa_rtr* );

// Tiskne OSPFv3 LSA Network Header cast packetu
void print_ospf3_lsa_net_hdr(const struct ospf3_lsa_net_hdr* );

// Tiskne OSPFv3 LSA Network cast packetu
void print_ospf3_lsa_net(const struct ospf3_lsa_net* );

// Tiskne OSPFv3 LSA Inter Area Prefix Header cast packetu
void print_ospf3_lsa_inter_area_prefix_hdr (const struct ospf3_lsa_inter_area_prefix_hdr* );

// Tiskne OSPFv3 LSA Inter Area Router cast packetu
void print_ospf3_lsa_inter_area_rtr(const struct ospf3_lsa_inter_area_rtr* );

// Tiskne OSPFv3 LSA AS-External Header cast packetu
void print_ospf3_lsa_asext_hdr (const struct ospf3_lsa_asext_hdr* );

// Tiskne OSPFv3 LSA Link cast packetu
int print_ospf3_lsa_link (const struct ospf3_lsa_link* );

// Tiskne OSPFv3 LSA Link Header cast packetu
void print_ospf3_lsa_link_hdr (const struct ospf3_lsa_link_hdr* );

// Tiskne OSPFv3 LSA Intra Area Prefix cast packetu
int print_ospf3_lsa_intra_area_prefix (const struct ospf3_lsa_intra_area_prefix* );

// Tiskne OSPFv3 LSA Intra Area Prefix Header cast packetu
void print_ospf3_lsa_intra_area_prefix_hdr (const struct ospf3_lsa_intra_area_prefix_hdr* );

/** Funkce tiskne obsah OSPFv3 LSA podle jeho typu
*@const struct ospf3_lsa* lsa - ukazatel na zacatek LSA
*/
int print_ospf3_lsa (const struct ospf3_lsa* );

#endif // OSPFV3_H_INCLUDED
