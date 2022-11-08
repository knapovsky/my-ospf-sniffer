/**
* Projekt do predmetu ISA - OSPFv2, OSPFv3 sniffer s vypsanim databaze
* soubor: 	ospfv2.c
*
* Autor:	Martin Knapovsky
* E-Mail:	xknapo02@stud.vutbr.cz
* Datum:	5.11.2011
*
* Popis souboru: Modul obsahujici struktury a funkce pro vypis OSPFv2
*                packetu.
*/

#include "sys.h"
#include "ospfv2.h"
#include "const.h"
#include <stdio.h>

// Tiskne OSPFv2 Hlavicku
void print_ospf2_header(const struct ospf2_header* ospf2_hdr){

    char router[BUFFER_LENGTH];
    char area[BUFFER_LENGTH];

    ipv4_to_str(router, ntohl(ospf2_hdr->router_id));
    ipv4_to_str(area, ntohl(ospf2_hdr->area_id));

    // pomocne pole znaku pro tisk typu OSPF packetu
    char* type;
    int type_id = ospf2_hdr->type;
    switch(type_id){
        case 1:
            type = "Hello";
            break;
        case 2:
            type = "DB Description";
            break;
        case 3:
            type = "LS Request";
            break;
        case 4:
            type = "LS Update";
            break;
        case 5:
            type = "LS Acknowledge";
            break;
        default:
            type = "Unknown";
            break;
   }

    printf("%s---OSPFv2 Header---\n", OSPF_HEADER_FORMAT);
    printf("%sVersion          : %d \n", OSPF_HEADER_FORMAT, ospf2_hdr->version);
    printf("%sOSPF2 Type       : %d (%s)\n", OSPF_HEADER_FORMAT, ospf2_hdr->type, type);
    printf("%sLength           : %d \n", OSPF_HEADER_FORMAT, ntohs(ospf2_hdr->length));
    printf("%sRouter ID        : %s \n", OSPF_HEADER_FORMAT, router);
    printf("%sArea ID          : %s \n", OSPF_HEADER_FORMAT, area);
    printf("%sChecksum         : 0x%X \n", OSPF_HEADER_FORMAT, ntohs(ospf2_hdr->checksum));
    printf("%sAuth. Type       : %d \n", OSPF_HEADER_FORMAT, ospf2_hdr->auth_type);
    printf("\n");

    return;
}

// Tiskne obsah OSPFv2 Hello casti OSPFv2 Packetu
void print_ospf2_hello(const struct ospf2_hello* ospf2_hl){

    char netmask[BUFFER_LENGTH];
    char designated[BUFFER_LENGTH];
    char backup_designated[BUFFER_LENGTH];
    ipv4_to_str(netmask, ntohl(ospf2_hl->mask));
    ipv4_to_str(designated, ntohl(ospf2_hl->d_rtr));
    ipv4_to_str(backup_designated, ntohl(ospf2_hl->bd_rtr));

    printf("%s---OSPFv2 Hello Packet---\n", OSPF_TYPE_FORMAT);
    printf("%sNetwork Mask     : %s \n", OSPF_TYPE_FORMAT, netmask);
    printf("%sHello Interval   : %d \n", OSPF_TYPE_FORMAT, ntohs(ospf2_hl->hello_interval));
    printf("%sOptions          : 0x%X \n", OSPF_TYPE_FORMAT, ospf2_hl->opts);
    printf("%sRTR Priority     : %d \n", OSPF_TYPE_FORMAT, ospf2_hl->rtr_priority);
    printf("%sRTR Dead Int.    : %d \n", OSPF_TYPE_FORMAT, ntohl(ospf2_hl->rtr_dead_interval));
    printf("%sDesignated R.    : %s \n", OSPF_TYPE_FORMAT, designated);
    printf("%sBackup Des. R.   : %s \n", OSPF_TYPE_FORMAT, backup_designated);
    printf("\n");

    return;

}

// Tiskne obsah OSPFv2 Database Description Hlavicky OSPFv2 Packetu
void print_ospf2_db_dscrp_hdr(const struct ospf2_db_dscrp_hdr* ospf2_db_dscrp_hr){

    printf("%s---Database Description Header---\n", OSPF_TYPE_FORMAT);
    printf("%sInterface MTU    : %d \n", OSPF_TYPE_FORMAT, ntohs(ospf2_db_dscrp_hr->iface_mtu));
    printf("%sOptions          : 0x%X \n", OSPF_TYPE_FORMAT, ospf2_db_dscrp_hr->opts);
    printf("%sDB Description   : 0x%X \n", OSPF_TYPE_FORMAT, ospf2_db_dscrp_hr->bits);
    printf("%sDD Sequence      : %d \n", OSPF_TYPE_FORMAT, ntohl(ospf2_db_dscrp_hr->dd_seq_num));
    printf("\n");

    return;
}

// Tiskne obsah OSPFv2 LSA Request Hlavicky OSPFv2 Packetu
void print_ospf2_ls_req_hdr(const struct ospf2_ls_req_hdr* ospf2_ls_req_hr){

    char link_state_id[BUFFER_LENGTH];
    char advertising_router[BUFFER_LENGTH];

    ipv4_to_str(link_state_id, ntohl(ospf2_ls_req_hr->ls_id));
    ipv4_to_str(advertising_router, ntohl(ospf2_ls_req_hr->adv_rtr));

    printf("%s---Link State Request Header---\n", OSPF_TYPE_FORMAT);
    printf("%sLS Adv. Type     : %d \n", OSPF_TYPE_FORMAT, ntohl(ospf2_ls_req_hr->type));
    printf("%sLink State ID    : %s \n", OSPF_TYPE_FORMAT, link_state_id);
    printf("%sAdvertising Rtr  : %s \n", OSPF_TYPE_FORMAT, advertising_router);
    printf("\n");

    return;
}

// Tiskne obsah OSPFv2 LSA Update Hlavicky OSPFv2 Packetu
void print_ospf2_ls_upd_hdr(const struct ospf2_ls_upd_hdr* ospf2_ls_upd_hr){

    printf("%s---LSA Update Header---\n",OSPF_TYPE_FORMAT);
    printf("%sNumber of LSA Up : %d \n", OSPF_TYPE_FORMAT, ntohl(ospf2_ls_upd_hr->num_lsa));
    printf("\n");

    return;
}

// Tiskne obsah OSPFv2 LSA Hlavicky
void print_ospf2_lsa_hdr(const struct ospf2_lsa_hdr* ospf2_lsa_hd){

    char link_state_id[BUFFER_LENGTH];
    char advertising_router[BUFFER_LENGTH];
    ipv4_to_str(link_state_id, ntohl(ospf2_lsa_hd->ls_id));
    ipv4_to_str(advertising_router, ntohl(ospf2_lsa_hd->adv_rtr));

    // pomocne pole znaku pro tisk typu LSA
    char* type;
    int type_id = ospf2_lsa_hd->type;
    switch(type_id){
        case 1:
            type = "Router-LSA";
            break;
        case 2:
            type = "Network-LSA";
            break;
        case 3:
            type = "Summary-LSA";
            break;
        case 4:
            type = "Summary-RTR-LSA";
            break;
        case 5:
            type = "AS-External";
            break;
        default:
            type = "Unknown";
            break;
    }

    printf("%s---LSA Header---\n", OSPF_LSA_HEADER_FORMAT);
    printf("%sAge              : %d \n", OSPF_LSA_HEADER_FORMAT, ntohs(ospf2_lsa_hd->age));
    printf("%sOptions          : 0x%X \n", OSPF_LSA_HEADER_FORMAT, ospf2_lsa_hd->opts);
    printf("%sType             : %d (%s)\n", OSPF_LSA_HEADER_FORMAT, ospf2_lsa_hd->type, type);
    printf("%sLink State ID    : %s \n", OSPF_LSA_HEADER_FORMAT, link_state_id);
    printf("%sAdvertising RTR  : %s \n", OSPF_LSA_HEADER_FORMAT, advertising_router);
    printf("%sSequence Number  : 0x%X \n", OSPF_LSA_HEADER_FORMAT, ntohl(ospf2_lsa_hd->seq_num));
    printf("%sLS Checksum      : 0x%X \n", OSPF_LSA_HEADER_FORMAT, ntohs(ospf2_lsa_hd->ls_chksum));
    printf("%sLength           : %d \n", OSPF_LSA_HEADER_FORMAT, ntohs(ospf2_lsa_hd->len));
    printf("\n");

    return;
}

// Tiskne obsah OSPFv2 LSA Router
void print_ospf2_lsa_rtr(const struct ospf2_lsa_rtr* ospf2_lsa_rt){

    printf("%s---LSA Router---\n", OSPF_LSA_FORMAT);
    printf("%sFlags            : 0x%X \n", OSPF_LSA_FORMAT, ospf2_lsa_rt->flags);
    printf("%sDummy            : 0x%X \n", OSPF_LSA_FORMAT, ospf2_lsa_rt->dummy);
    printf("%sNumber of Links  : %d \n", OSPF_LSA_FORMAT, ntohs(ospf2_lsa_rt->nlinks));
    printf("\n");

    return;
}

// Tiskne obsah OSPFv2 LSA Router Link
void print_ospf2_lsa_rtr_link(const struct ospf2_lsa_rtr_link* ospf2_lsa_rtr_ln){

    char link_state_id[BUFFER_LENGTH];
    char data[BUFFER_LENGTH];
    ipv4_to_str(link_state_id, ntohl(ospf2_lsa_rtr_ln->id));
    ipv4_to_str(data, ntohl(ospf2_lsa_rtr_ln->data));

    printf("%s---LSA Router Link---\n", OSPF_LSA_FORMAT);
    printf("%sLink State ID    : %s \n", OSPF_LSA_FORMAT, link_state_id);
    printf("%sData             : %s \n", OSPF_LSA_FORMAT, data);
    printf("%sType             : %d \n", OSPF_LSA_FORMAT, ospf2_lsa_rtr_ln->type);
    printf("%sNumber of TOS    : %d \n", OSPF_LSA_FORMAT, ospf2_lsa_rtr_ln->num_tos);
    printf("%sMetric           : %d \n", OSPF_LSA_FORMAT, ntohs(ospf2_lsa_rtr_ln->metric));
    printf("\n");

    return;
}

// Tiskne samotne "Attached Router" routery obasazene v Network-LSA OSPFv2
void print_ospf2_lsa_net_att(const struct ospf2_lsa_net_att* lsa){

    char ip[BUFFER_LENGTH];
    ipv4_to_str(ip, ntohl(lsa->att_rtr));

    printf("%s---LSA Network---\n", OSPF_LSA_FORMAT);
    printf("%sAttached RTR   : %s\n", OSPF_LSA_FORMAT, ip);
    printf("\n");

    return;
}

// Tiskne obsah OSPFv2 LSA Network
void print_ospf2_lsa_net(const struct ospf2_lsa_net* ospf2_lsa_nt){

    char mask[BUFFER_LENGTH];
    ipv4_to_str(mask, ntohl(ospf2_lsa_nt->mask));

    printf("%s---LSA Network---\n", OSPF_LSA_FORMAT);
    printf("%sMask             : %s \n", OSPF_LSA_FORMAT, mask);
    printf("\n");

    const struct ospf2_lsa_hdr* hdr = (struct ospf2_lsa_hdr*)((int)ospf2_lsa_nt - sizeof(struct ospf2_lsa_hdr));
    int length = ntohs(hdr->len);
    // Tisk samotnych LSA Intra Area Prefix Informaci
    int i;
    for(i = 0; (i + sizeof(struct ospf2_lsa_net) + sizeof(struct ospf2_lsa_hdr)) < length; i+=sizeof(struct ospf2_lsa_net_att)){
        print_ospf2_lsa_net_att((struct ospf2_lsa_net_att*)((int)(ospf2_lsa_nt) + sizeof(struct ospf2_lsa_net) + i));
    }

    return;
}

// Tiskne obsah OSPFv2 LSA Network Link
void print_ospf2_lsa_net_link(const struct ospf2_lsa_net_link* ospf2_lsa_net_ln){

    printf("%s---LSA Network Link---\n", OSPF_LSA_FORMAT);
    printf("%sWTF?\n", OSPF_LSA_FORMAT);
    printf("\n");

    return;
}

// Tiskne obsah OSPFv2 LSA Summary
void print_ospf2_lsa_sum(const struct ospf2_lsa_sum* ospf2_lsa_summary){

    char mask[BUFFER_LENGTH];
    ipv4_to_str(mask, ntohl(ospf2_lsa_summary->mask));

    printf("%s---LSA Summary---\n", OSPF_LSA_FORMAT);
    printf("%sMask             : %s \n", OSPF_LSA_FORMAT, mask);
    printf("%sMetric           : %d \n", OSPF_LSA_FORMAT, ntohl(ospf2_lsa_summary->metric) & 0x0fff);
    printf("\n");

    return;
}

// Tiskne obsah OSPFv2 LSA AS-External
void print_ospf2_lsa_asext(const struct ospf2_lsa_asext* ospf2_lsa_asxt){

    char mask[BUFFER_LENGTH];
    char fw_addr[BUFFER_LENGTH];
    ipv4_to_str(mask, ntohl(ospf2_lsa_asxt->mask));
    ipv4_to_str(fw_addr, ntohl(ospf2_lsa_asxt->fw_addr));

    printf("%s---LSA ASEXT---\n", OSPF_LSA_FORMAT);
    printf("%sMask             : %s \n", OSPF_LSA_FORMAT, mask);
    printf("%sMetric           : %d \n", OSPF_LSA_FORMAT, ntohl(ospf2_lsa_asxt->metric) & 0x0fff);
    printf("%sFW Addr          : %s \n", OSPF_LSA_FORMAT, fw_addr);
    printf("%sExternal Tag     : %d \n", OSPF_LSA_FORMAT, ntohl(ospf2_lsa_asxt->ext_tag));
    printf("\n");

    return;
}

// Tiskne obsah OSPFv2 LLS Data Bloku
void print_ospf2_lls_data_block(const struct ospf2_lls_data_block* ospf2_lls_data_blck){

    printf("%s---LLS Data Block---\n", OSPF_LSA_FORMAT);
    printf("%sChecksum         : 0x%X \n", OSPF_LSA_FORMAT, ntohs(ospf2_lls_data_blck->checksum));
    printf("%sLLS Data Length  : %d \n", OSPF_LSA_FORMAT, ntohs(ospf2_lls_data_blck->data_length) * 4);
    printf("\n");

    return;
}

/** Funkce tiskne obsah LSA podle jeho typu
*@const struct ospf2_lsa* ospf2_ls - ukazatel na lsa soucast ospfv2 packetu
*@const u_char *packet - ukazatel na zacatek packetu - pro tisk dodatecnych informaci
*@int size_ipv4 - velikost ipv4 packetu pro tisk dodatecnych informaci
*/
int print_ospf2_lsa(const struct ospf2_lsa* ospf2_ls, const unsigned char *packet, int size_ipv4){
    // typ LSA
    int type = ospf2_ls->hdr.type;
    // Tisk LSA hlavicky
    print_ospf2_lsa_hdr(&ospf2_ls->hdr);
    // Velikost LSA s hlavickou
    int size = ntohs(ospf2_ls->hdr.len);
		int links;
		int offset;
		struct ospf2_lsa_rtr_link* pointer;
    // Tisk LSA informace dle typu LSA zjisteneho z hlavicky
    switch (type){
        // LSA-Router
        case LSA_TYPE_ROUTER:
            print_ospf2_lsa_rtr(&ospf2_ls->data.rtr);
            // Pocet Adres
            links = ntohs(ospf2_ls->data.rtr.nlinks);
            // Relativni ukazatel na soucasnou pozici v packetu
            offset = 0;
            // Absolutni pozice v packetu
            pointer = (struct ospf2_lsa_rtr_link*) (packet + SIZE_ETHERNET + size_ipv4 + OSPF2HEADER_LENGTH + sizeof(struct ospf2_lsa_hdr) + sizeof(struct ospf2_lsa_rtr) + 4);
            // Postupne vytisteni vsech LSA informaci
            while(links > 0){
                print_ospf2_lsa_rtr_link(pointer);
                links--;
                offset += sizeof(struct ospf2_lsa_rtr_link);
                // posunuti relativniho ukazatele
                pointer = (struct ospf2_lsa_rtr_link*) (packet + SIZE_ETHERNET + size_ipv4 + OSPF2HEADER_LENGTH + sizeof(struct ospf2_lsa_hdr) + sizeof(struct ospf2_lsa_rtr) + 4 + offset);
            }

            break;
        // LSA-Network
        case LSA_TYPE_NETWORK:
            print_ospf2_lsa_net(&ospf2_ls->data.net);
            break;
        // LSA-SUM-Network
        case LSA_TYPE_SUM_NETWORK:
            print_ospf2_lsa_sum(&ospf2_ls->data.sum);
            break;
        // LSA-Sum-Router
        case LSA_TYPE_SUM_ROUTER:
            printf("%sLSA not suppported\n", OSPF_LSA_FORMAT);
            break;
        // LSA-AS-External
        case LSA_TYPE_EXTERNAL:
            print_ospf2_lsa_asext(&ospf2_ls->data.asext);
            break;
    }

    // Paranoidni osetreni navratove hodnoty
    return (size>0)?size:0;
}
