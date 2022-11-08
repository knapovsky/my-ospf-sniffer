/**
* Projekt do predmetu ISA - OSPFv2, OSPFv3 sniffer s vypsanim databaze
* soubor: 	ospfv2.h
*
* Autor:	Martin Knapovsky
* E-Mail:	xknapo02@stud.vutbr.cz
* Datum:	5.11.2011
*
* Popis souboru: Modul obsahujici struktury a funkce pro vypis OSPFv2
*                packetu.
*/

#ifndef OSPFV2_H_INCLUDED
#define OSPFV2_H_INCLUDED

#include <netinet/in.h>

#define LSA_TYPE_ROUTER         1
#define LSA_TYPE_NETWORK        2
#define LSA_TYPE_SUM_NETWORK    3
#define LSA_TYPE_SUM_ROUTER     4
#define LSA_TYPE_EXTERNAL       5

#define LINK_TYPE_POINTTOPOINT  1
#define LINK_TYPE_TRANSIT_NET   2
#define LINK_TYPE_STUB_NET      3
#define LINK_TYPE_VIRTUAL       4

// LSA headers
#define LSA_METRIC_MASK		0x00ffffff
#define LSA_ASEXT_E_FLAG	0x80000000

// Hlavicka OSPFv2
typedef struct ospf2_header{

    u_int8_t  version;
    u_int8_t  type;
    u_int16_t length;
    u_int32_t router_id;
    u_int32_t area_id;
    u_int16_t checksum;
    u_int16_t auth_type;
    u_int8_t  auth_data[8];

} ospf2_header;

// type 1 - Hello
typedef struct ospf2_hello{

    u_int32_t   mask;
    u_int16_t   hello_interval;
    u_int8_t    opts;
    u_int8_t    rtr_priority;
    u_int32_t   rtr_dead_interval;
    u_int32_t   d_rtr;
    u_int32_t   bd_rtr;

} ospf2_hello;

// type 2 - Database Description
typedef struct ospf2_db_dscrp_hdr{

    u_int16_t   iface_mtu;
    u_int8_t    opts;
    u_int8_t    bits;
    u_int32_t   dd_seq_num;

} ospf2_db_dscrp_hdr;

// type 3 - LSA Request
typedef struct ospf2_ls_req_hdr{

    u_int32_t   type;
    u_int32_t   ls_id;
    u_int32_t   adv_rtr;

} ospf2_ls_req_hdr;

// type 4 - LSA Update
typedef struct ospf2_ls_upd_hdr {

    u_int32_t   num_lsa;

} ospf2_ls_upd_hdr;

// type 5 - LSA Acknowledge - neni potreba - OSPFv2 Header + LSA

// LSA Router
typedef struct ospf2_lsa_rtr {

	u_int8_t		flags;
	u_int8_t		dummy;
	u_int16_t		nlinks;

} ospf2_lsa_rtr;

// LSA Router Link
typedef struct ospf2_lsa_rtr_link {

	u_int32_t		id;
	u_int32_t		data;
	u_int8_t		type;
	u_int8_t		num_tos;
	u_int16_t		metric;

} ospf2_lsa_rtr_link;

// LSA Network Header
typedef struct ospf2_lsa_net {

	u_int32_t		mask;

} ospf2_lsa_net;

// LSA Network Attached
typedef struct ospf2_lsa_net_att {

    u_int32_t		att_rtr;

} ospf2_lsa_net_att;

// LSA Network Link
typedef struct ospf2_lsa_net_link {

	u_int32_t		att_rtr;

} ospf2_lsa_net_link;

// LSA Summary
typedef struct ospf2_lsa_sum {

	u_int32_t		mask;
	u_int32_t		metric;

} ospf2_lsa_sum;

// LSA AS-External
typedef struct ospf2_lsa_asext {

	u_int32_t		mask;
	u_int32_t		metric;
	u_int32_t		fw_addr;
	u_int32_t		ext_tag;

} ospf2_lsa_asext;

// LSA Header
typedef struct ospf2_lsa_hdr {

	u_int16_t		age;
	u_int8_t		opts;
	u_int8_t		type;
	u_int32_t		ls_id;
	u_int32_t		adv_rtr;
	u_int32_t		seq_num;
	u_int16_t		ls_chksum;
	u_int16_t		len;

} ospf2_lsa_hdr;

// LLS Data Block
typedef struct ospf2_lls_data_block {

    u_int16_t        checksum;
    u_int16_t        data_length;

} ospf2_lls_data_block;

// Souhrnna struktura pro LSA
typedef struct ospf2_lsa {

    struct ospf2_lsa_hdr    hdr;
    union {
        struct ospf2_lsa_rtr    rtr;
        struct ospf2_lsa_net    net;
        struct ospf2_lsa_sum    sum;
        struct ospf2_lsa_asext  asext;
    } data;

} ospf2_lsa;

// Tiskne OSPFv2 Hlavicku
void print_ospf2_header(const struct ospf2_header* );

// Tiskne obsah OSPFv2 Hello casti OSPFv2 Packetu
void print_ospf2_hello(const struct ospf2_hello* );

// Tiskne obsah OSPFv2 Database Description Hlavicky OSPFv2 Packetu
void print_ospf2_db_dscrp_hdr(const struct ospf2_db_dscrp_hdr* );

// Tiskne obsah OSPFv2 LSA Request Hlavicky OSPFv2 Packetu
void print_ospf2_ls_req_hdr(const struct ospf2_ls_req_hdr* );

// Tiskne obsah OSPFv2 LSA Update Hlavicky OSPFv2 Packetu
void print_ospf2_ls_upd_hdr(const struct ospf2_ls_upd_hdr* );

// Tiskne obsah OSPFv2 LSA Hlavicky
void print_ospf2_lsa_hdr(const struct ospf2_lsa_hdr* );

// Tiskne obsah OSPFv2 LSA Router
void print_ospf2_lsa_rtr(const struct ospf2_lsa_rtr* );

// Tiskne obsah OSPFv2 LSA Router Link
void print_ospf2_lsa_rtr_link(const struct ospf2_lsa_rtr_link* );

// Tiskne samotne "Attached Router" routery obasazene v Network-LSA OSPFv2
void print_ospf2_lsa_net_att(const struct ospf2_lsa_net_att* );

// Tiskne obsah OSPFv2 LSA Network
void print_ospf2_lsa_net(const struct ospf2_lsa_net* );

// Tiskne obsah OSPFv2 LSA Network Link
void print_ospf2_lsa_net_link(const struct ospf2_lsa_net_link* );

// Tiskne obsah OSPFv2 LSA Summary
void print_ospf2_lsa_sum(const struct ospf2_lsa_sum* );

// Tiskne obsah OSPFv2 LSA AS-External
void print_ospf2_lsa_asext(const struct ospf2_lsa_asext* );

// Tiskne obsah OSPFv2 LLS Data Bloku
void print_ospf2_lls_data_block(const struct ospf2_lls_data_block* );

/** Funkce tiskne obsah LSA podle jeho typu
*@const struct ospf2_lsa* ospf2_ls - ukazatel na lsa soucast ospfv2 packetu
*@const u_char *packet - ukazatel na zacatek packetu - pro tisk dodatecnych informaci
*@int size_ipv4 - velikost ipv4 packetu pro tisk dodatecnych informaci
*/
int print_ospf2_lsa(const struct ospf2_lsa*, const unsigned char*, int);

#endif // OSPFV2_H_INCLUDED
