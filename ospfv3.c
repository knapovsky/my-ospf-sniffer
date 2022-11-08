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

#include "sys.h"
#include "ospfv3.h"
#include "const.h"
#include "binary.c"
#include <stdio.h>

// Tiskne hlavicku OSPFv3
void print_ospf3_header(const struct ospf3_header* hdr){

    char router_id[BUFFER_LENGTH];
    char area_id[BUFFER_LENGTH];
    ipv4_to_str(router_id, ntohl(hdr->router_id));
    ipv4_to_str(area_id, ntohl(hdr->area_id));
    
    // pomocne pole znaku pro tisk typu OSPF packetu
    char* type;
    int type_id = hdr->type;
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
            

    printf("%s---OSPFv3 Header---\n", OSPF_TYPE_FORMAT);
    printf("%sVersion          : %d\n", OSPF_HEADER_FORMAT, hdr->version);
    printf("%sType             : %d (%s)\n", OSPF_HEADER_FORMAT, hdr->type, type);
    printf("%sPacket Length    : %d\n", OSPF_HEADER_FORMAT, ntohs(hdr->length));
    printf("%sRouter ID        : %s\n", OSPF_HEADER_FORMAT, router_id);
    printf("%sArea ID          : %s\n", OSPF_HEADER_FORMAT, area_id);
    printf("%sChecksum         : 0x%X\n", OSPF_HEADER_FORMAT, ntohs(hdr->checksum));
    printf("%sInstance ID      : %d\n", OSPF_HEADER_FORMAT, hdr->instance_id);
    printf("\n");

    return;
}

// Tiskne OSPFv3 Hello cast packetu
void print_ospf3_hello(const struct ospf3_hello* hl, int neighbor){

    // Pole pro ulozeni prevedenych adres
    char interface_id[BUFFER_LENGTH];
    char designated_rtr_id[BUFFER_LENGTH];
    char backup_designated_rtr_id[BUFFER_LENGTH];
    char neighbor_id[BUFFER_LENGTH];
    ipv4_to_str(interface_id, ntohl(hl->interface_id));
    ipv4_to_str(designated_rtr_id, ntohl(hl->d_rtr));
    ipv4_to_str(backup_designated_rtr_id, ntohl(hl->bd_rtr));
    ipv4_to_str(neighbor_id, ntohl(hl->neighbor_id));

    printf("%s---Hello Packet---\n", OSPF_TYPE_FORMAT);
    printf("%sInterface ID     : %d\n", OSPF_TYPE_FORMAT, ntohl(hl->interface_id));
    printf("%sRouter Priority  : %d\n", OSPF_TYPE_FORMAT, (ntohl(hl->opts) & HELLO_PRIORITY_MASK) >> 24);
    printf("%sOptions          : 0x%X\n", OSPF_TYPE_FORMAT, (ntohl(hl->opts) & HELLO_OPTIONS_MASK));
    printf("%sHello Interval   : %d\n", OSPF_TYPE_FORMAT, ntohs(hl->hello_interval));
    printf("%sRTR Dead Interval: %d\n", OSPF_TYPE_FORMAT, ntohs(hl->rtr_dead_interval));
    printf("%sDesignated RTR ID: %s\n", OSPF_TYPE_FORMAT, designated_rtr_id);
    printf("%sBD RTR ID        : %s\n", OSPF_TYPE_FORMAT, backup_designated_rtr_id);
    if(neighbor){
        printf("%sNeighbor ID      : %s\n", OSPF_TYPE_FORMAT, neighbor_id);
    }
    printf("\n");

    return;
}

// Tiskne OSPFv3 Database Description cast packetu
void print_ospf3_db_dscrp_hdr(const struct ospf3_db_dscrp_hdr* db){

    printf("%s---Database Description---\n", OSPF_TYPE_FORMAT);
    printf("%sOptions          : 0x%X\n", OSPF_TYPE_FORMAT, ntohl(db->opts) & DB_OPTIONS_MASK);
    printf("%sInterface MTU    : %d\n", OSPF_TYPE_FORMAT, ntohs(db->iface_mtu));
    printf("%sBits             : 0x%X\n", OSPF_TYPE_FORMAT, db->bits);
    printf("%sDD Sequence NUM  : %d\n", OSPF_TYPE_FORMAT, ntohl(db->dd_seq_num));
    printf("\n");

    return;
}

// Tiskne OSPFv3 LSA Request cast packetu
void print_ospf3_ls_req_hdr(const struct ospf3_ls_req_hdr* req){

    char ls_id[BUFFER_LENGTH];
    char adv_rtr[BUFFER_LENGTH];
    ipv4_to_str(ls_id, ntohl(req->ls_id));
    ipv4_to_str(adv_rtr, ntohl(req->adv_rtr));

    printf("%s---Link State Request Header---\n", OSPF_TYPE_FORMAT);
    printf("%sType             : 0x%X\n", OSPF_TYPE_FORMAT, ntohs(req->type));
    printf("%sLink State ID    : %s\n", OSPF_TYPE_FORMAT, ls_id);
    printf("%sAdvertising RTR  : %s\n", OSPF_TYPE_FORMAT, adv_rtr);
    printf("\n");

    return;
}

// Tiskne OSPFv3 LSA Update cast packetu
void print_ospf3_ls_upd_hdr(const struct ospf3_ls_upd_hdr* upd){

    printf("%s---Link State Update Header---\n", OSPF_TYPE_FORMAT);
    printf("%sNumber of LSA    : %d", OSPF_TYPE_FORMAT, ntohl(upd->num_lsa));
    printf("\n");

}

// Tiskne OSPFv3 LSA Header
void print_ospf3_lsa_hdr(const struct ospf3_lsa_hdr* hdr){

    char ls_id[BUFFER_LENGTH];
    char adv_rtr[BUFFER_LENGTH];
    ipv4_to_str(ls_id, ntohl(hdr->ls_id));
    ipv4_to_str(adv_rtr, ntohl(hdr->adv_rtr));
    
    // pomocne pole znaku pro tisk typu LSA
    char* type;
    int type_id = ntohs(hdr->type);
    switch(type_id){
        case 0x2001:
            type = "Router-LSA";
            break;
        case 0x2002:
            type = "Network-LSA";
            break;
        case 0x2003:
            type = "Inter-Area-Prefix-LSA";
            break;
        case 0x2004:
            type = "Inter-Area-Router-LSA";
            break;
        case 0x4005:
            type = "AS-External-LSA";
            break;
        case 0x2006:
            type = "Unknown";
            break;
        case 0x0008:
            type = "Link-LSA";
            break;
        case 0x2009:
            type = "Intra-Area-Prefix-LSA";
            break;
        default:
            type = "Unknown";
            break;
    }

    printf("%s---Link State Advertisment Header---\n", OSPF_LSA_HEADER_FORMAT);
    printf("%sAge              : %d\n", OSPF_LSA_HEADER_FORMAT, ntohs(hdr->age));
    printf("%sLSA Type         : 0x%X (%s)\n", OSPF_LSA_HEADER_FORMAT, ntohs(hdr->type), type);
    printf("%sLSA Handling     : %d\n", OSPF_LSA_HEADER_FORMAT, (ntohs(hdr->type) & B16(10000000,00000000)) >> 15);
    printf("%sFlooding Scope   : %X\n", OSPF_LSA_HEADER_FORMAT, (ntohs(hdr->type) & B16(01100000,00000000)) >> 13);
    printf("%sLSA Function Code: %X\n", OSPF_LSA_HEADER_FORMAT, (ntohs(hdr->type) & B16(00011111,11111111)));
    printf("%sLink State ID    : %s\n", OSPF_LSA_HEADER_FORMAT, ls_id);
    printf("%sAdvertising RTR  : %s\n", OSPF_LSA_HEADER_FORMAT, adv_rtr);
    printf("%sLS Sequence NUM  : 0x%X\n", OSPF_LSA_HEADER_FORMAT, ntohl(hdr->seq_num));
    printf("%sLS Checksum      : 0x%X\n", OSPF_LSA_HEADER_FORMAT, ntohs(hdr->ls_chksum));
    printf("%sLength           : %d\n", OSPF_LSA_HEADER_FORMAT, ntohs(hdr->len));
    printf("\n");

    return;
}

// Tiskne OSPFv3 LSA Router Header cast packetu
void print_ospf3_lsa_rtr_hdr(const struct ospf3_lsa_rtr_hdr* hdr){

    printf("%s---Router-LSA Header---\n", OSPF_LSA_FORMAT);
    printf("%sBits             : 0x%X\n", OSPF_LSA_FORMAT, (ntohl(hdr->opts) & 0xff000000) >> 24);
    printf("%sOptions          : 0x%X\n", OSPF_LSA_FORMAT, (ntohl(hdr->opts) & 0x00ffffff));
    printf("\n");

    return;
}

// Tiskne OSPFv3 LSA Router cast packetu
void print_ospf3_lsa_rtr(const struct ospf3_lsa_rtr* rtr){

    char if_id[BUFFER_LENGTH];
    char n_if_id[BUFFER_LENGTH];
    char n_rtr_id[BUFFER_LENGTH];
    ipv4_to_str(if_id, ntohl(rtr->if_id));
    ipv4_to_str(n_if_id, ntohl(rtr->n_if_id));
    ipv4_to_str(n_rtr_id, ntohl(rtr->n_rtr_id));
    
    // Urceni typu Router-LSA pro vypis
    int type_id = rtr->type;
    char* type;
    switch(type_id){
        case 1:
            type = "Point-to-Point connection to another router";
            break;
        case 2:
            type = "Connection to a transit network";
            break;
        case 3:
            type = "Reserved";
            break;
        case 4:
            type = "Virtual Link";
            break;
        default:
            type = "Unknown";
            break;
    }

    printf("%s---Router-LSA---\n", OSPF_LSA_FORMAT);
    printf("%sType             : %d (%s)\n", OSPF_LSA_FORMAT, rtr->type, type);
    printf("%sMetric           : %d\n", OSPF_LSA_FORMAT, ntohs(rtr->metric));
    printf("%sInterface ID     : %d\n", OSPF_LSA_FORMAT, ntohl(rtr->if_id));
    printf("%sNeighbor IF ID   : %d\n", OSPF_LSA_FORMAT, ntohl(rtr->n_if_id));
    printf("%sNeighbor RTR ID  : %s\n", OSPF_LSA_FORMAT, n_rtr_id);
    printf("\n");

    return;
}

// Tiskne OSPFv3 LSA Network Header cast packetu
void print_ospf3_lsa_net_hdr(const struct ospf3_lsa_net_hdr* hdr){

    printf("%s---Network-LSA Header---\n", OSPF_LSA_FORMAT);
    printf("%sOptions          : 0x%X\n", OSPF_LSA_FORMAT, (ntohl(hdr->opts) & 0x00ffffff));
    printf("\n");

    return;
}

// Tiskne OSPFv3 LSA Network cast packetu
void print_ospf3_lsa_net(const struct ospf3_lsa_net* lsa){

    char att_rtr[BUFFER_LENGTH];
    ipv4_to_str(att_rtr, ntohl(lsa->att_rtr));

    printf("%s---Network-LSA---\n", OSPF_LSA_FORMAT);
    printf("%sAttached Router  : %s\n", OSPF_LSA_FORMAT, att_rtr);
    printf("\n");

    return;
}

// Tiskne OSPFv3 LSA Inter Area Prefix Header cast packetu
void print_ospf3_lsa_inter_area_prefix_hdr (const struct ospf3_lsa_inter_area_prefix_hdr* hdr){

    printf("%s---Inter-Area Prefix LSA Header---\n", OSPF_LSA_FORMAT);
    printf("%sMetric           : %d\n", OSPF_LSA_FORMAT, ntohl(hdr->metric) & 0x00ffffff);
    printf("%sPrefix Length    : %d\n", OSPF_LSA_FORMAT, hdr->p_len);
    printf("%sPrefix Options   : 0x%X\n", OSPF_LSA_FORMAT, hdr->p_opts);
    //printf("\n");

    return;
}

// Tiskne OSPFv3 LSA Inter Area Router cast packetu
void print_ospf3_lsa_inter_area_rtr(const struct ospf3_lsa_inter_area_rtr* lsa){

    char dst_rtr_id[BUFFER_LENGTH];
    ipv4_to_str(dst_rtr_id, ntohl(lsa->dst_rtr_id));

    printf("%s---Inter-Area-Router LSA---\n", OSPF_LSA_FORMAT);
    printf("%sOptions          : 0x%X\n", OSPF_LSA_FORMAT, (ntohl(lsa->opts)) & 0x00ffffff);
    printf("%sMetric           : %d\n", OSPF_LSA_FORMAT, (ntohl(lsa->metric)) & 0x00ffffff);
    printf("%sDest. RTR ID     : %s\n", OSPF_LSA_FORMAT, dst_rtr_id);
    printf("\n");

    return;
}

// Tiskne OSPFv3 LSA AS-External Header cast packetu
void print_ospf3_lsa_asext_hdr (const struct ospf3_lsa_asext_hdr* hdr){

    printf("%s---AS-External-LSA---\n", OSPF_LSA_FORMAT);
    printf("%sMetric           : 0x%X\n", OSPF_LSA_FORMAT, ntohl(hdr->metric));
    printf("%sPrefix Length    : %d\n", OSPF_LSA_FORMAT, hdr->p_len);
    printf("%sPrefix Options   : 0x%X\n", OSPF_LSA_FORMAT, hdr->p_opts);
    printf("%sReferenced LS    : %d\n", OSPF_LSA_FORMAT, ntohs(hdr->ref_ls));
    printf("%sAddress Prefix   : ", OSPF_LSA_FORMAT);
    print_address_prefix((char*)((int) hdr + sizeof(struct ospf3_lsa_asext_hdr)), hdr->p_len);
    printf("\n");
    printf("\n");

    return;
}

// Tiskne OSPFv3 LSA Link cast packetu
int print_ospf3_lsa_link (const struct ospf3_lsa_link* lsa){

    printf("%s---Link-LSA---\n", OSPF_LSA_FORMAT);
    printf("%sPrefix Length    : %d\n", OSPF_LSA_FORMAT, lsa->p_len);
    printf("%sPrefix Options   : 0x%X\n", OSPF_LSA_FORMAT, lsa->p_opts);
    printf("%sAddress Prefix   : ", OSPF_LSA_FORMAT);
    // Prevadi prefix na retezec a tiskne ho
    print_address_prefix((char*)((int) lsa + sizeof(struct ospf3_lsa_link)), lsa->p_len);
    printf("\n");
    printf("\n");

    // vypocet delky LSA Link
    int length = (lsa->p_len%8)?(lsa->p_len/8)+1:(lsa->p_len);
    return (int)(length + sizeof(struct ospf3_lsa_link));
}

// Tiskne OSPFv3 LSA Link Header cast packetu
void print_ospf3_lsa_link_hdr (const struct ospf3_lsa_link_hdr* hdr){

    char address[INET6_ADDRSTRLEN];
    ipv6_to_str_unexpanded(address, &(hdr->addr));

    printf("%s---Link-LSA Header---\n", OSPF_LSA_FORMAT);
    printf("%sRouter Priority  : %d\n", OSPF_LSA_FORMAT, ((ntohl(hdr->opts)) & 0xff000000) >> 24);
    printf("%sOptions          : 0x%X\n", OSPF_LSA_FORMAT, (ntohl(hdr->opts)) & 0x00ffffff);
    printf("%sLink-Local IF ADR: %s\n", OSPF_LSA_FORMAT, address);
    printf("%sNumber of Pref.  : %d\n", OSPF_LSA_FORMAT, ntohl(hdr->num_pref));
    printf("\n");

    // Tisk samotnych LSA Link Informaci
    int i = 0;
    int offset = 0;
    int num_pref = ntohl(hdr->num_pref);
    while(i < num_pref){
        offset += print_ospf3_lsa_link((struct ospf3_lsa_link*)((int)hdr + sizeof(struct ospf3_lsa_link_hdr) + offset));
        i++;
    }

    return;
}

// Tiskne OSPFv3 LSA Intra Area Prefix cast packetu
int print_ospf3_lsa_intra_area_prefix (const struct ospf3_lsa_intra_area_prefix* lsa){

    printf("%s---Intra-Area-Prefix-LSA---\n", OSPF_LSA_FORMAT);
    printf("%sPrefix Length    : %d\n", OSPF_LSA_FORMAT, lsa->p_len);
    printf("%sPrefix Options   : 0x%X\n", OSPF_LSA_FORMAT, lsa->p_opts);
    printf("%sMetric           : %d\n", OSPF_LSA_FORMAT, ntohs(lsa->metric));
    printf("%sAddress Prefix   : ", OSPF_LSA_FORMAT);
    // Prevadi prefix na retezec a tiskne ho
    print_address_prefix((char*)((int) lsa + sizeof(struct ospf3_lsa_intra_area_prefix)), lsa->p_len);
    printf("\n");
    printf("\n");

    // vypocet delky LSA Link
    int length = (lsa->p_len%8)?(lsa->p_len/8)+1:(lsa->p_len);
    return (int)(length + sizeof(struct ospf3_lsa_intra_area_prefix));
}

// Tiskne OSPFv3 LSA Intra Area Prefix Header cast packetu
void print_ospf3_lsa_intra_area_prefix_hdr (const struct ospf3_lsa_intra_area_prefix_hdr* hdr){

    char ls_id[BUFFER_LENGTH];
    char adv_rtr[BUFFER_LENGTH];
    ipv4_to_str(ls_id, ntohl(hdr->ref_ls_id));
    ipv4_to_str(adv_rtr, ntohl(hdr->ref_adv_rtr));

    printf("%s---Intra-Area-Prefix-LSA Header---\n", OSPF_LSA_FORMAT);
    printf("%sNumber of Pref.  : %d\n", OSPF_LSA_FORMAT, ntohs(hdr->num_pref));
    printf("%sRef. LS Type     : 0x%X\n", OSPF_LSA_FORMAT, ntohs(hdr->type));
    printf("%sRef. LS ID       : %s\n", OSPF_LSA_FORMAT, ls_id);
    printf("%sRef. Adv. Router : %s\n", OSPF_LSA_FORMAT, adv_rtr);
    printf("\n");

    // Tisk samotnych LSA Intra Area Prefix Informaci
    int i = 0;
    int offset = 0;
    int num_pref = ntohs(hdr->num_pref);
    while(i < num_pref){
        offset += print_ospf3_lsa_intra_area_prefix((struct ospf3_lsa_intra_area_prefix*)((int)hdr + sizeof(struct ospf3_lsa_intra_area_prefix_hdr) + offset));
        i++;
    }

    return;
}

/** Funkce tiskne obsah OSPFv3 LSA podle jeho typu
*const struct ospf3_lsa* lsa - ukazatel na zacatek LSA
*const u_char *packet - ukazatel na zacatek packetu pro tisk dodatecnych informaci
*/
int print_ospf3_lsa (const struct ospf3_lsa* lsa){

    // Typ LSA
    int type = ntohs(lsa->hdr.type);
    // Tisk LSA hlavciky
    print_ospf3_lsa_hdr(&lsa->hdr);
    // Velikost LSA
    int size = ntohs(lsa->hdr.len);
    // Relativni pozice v LSA
    int offset = 0;
    const struct ospf3_lsa_rtr* my_lsa_rtr;
    const struct ospf3_lsa_net* my_lsa_net;

    // Tisk Informaci dle Typu LSA
    switch (type){
        // LSA-Router
        case ROUTER_LSA:
            if(size > 24){
                print_ospf3_lsa_rtr_hdr((struct ospf3_lsa_rtr_hdr*)((int)(lsa) + OSPF3_LSA_HEADER_SIZE ));
                while((offset + OSPF3_LSA_HEADER_SIZE + sizeof(struct ospf3_lsa_rtr_hdr)) < size){
                    my_lsa_rtr = (struct ospf3_lsa_rtr*)((int)lsa + OSPF3_LSA_HEADER_SIZE +  + sizeof(struct ospf3_lsa_rtr_hdr) + offset);
                    print_ospf3_lsa_rtr(my_lsa_rtr);
                    offset += sizeof(ospf3_lsa_rtr);
                }
            }
            break;
        // LSA-Network
        case NETWORK_LSA:
            print_ospf3_lsa_net_hdr((struct ospf3_lsa_net_hdr*) ((int)lsa + OSPF3_LSA_HEADER_SIZE));
            while((offset + OSPF3_LSA_HEADER_SIZE + sizeof(struct ospf3_lsa_net_hdr)) < size){
                my_lsa_net = (struct ospf3_lsa_net*)((int)lsa + OSPF3_LSA_HEADER_SIZE + sizeof(ospf3_lsa_net_hdr) + offset);
                print_ospf3_lsa_net(my_lsa_net);
                offset += sizeof(struct ospf3_lsa_net);
            }
            break;
        // LSA-Intra-Area-Prefix
        case IA_PREFIX_LSA:
            print_ospf3_lsa_inter_area_prefix_hdr(&(lsa->data.ia_p_hdr));
            // Prevod prefixu a jeho tisk
            printf("%sAddress Prefix   : ", OSPF_LSA_FORMAT);
            print_address_prefix((char*)((&(lsa->data.ia_p_hdr)) + sizeof(struct ospf3_lsa_inter_area_prefix_hdr)), lsa->data.ia_p_hdr.p_len);
            printf("\n");
            printf("\n");
            break;
        // LSA-Intra-Area-Router
        case IA_RTR_LSA:
            print_ospf3_lsa_inter_area_rtr(&(lsa->data.ia_rtr));
            break;
        // LSA-AS-External
        case ASEXT_LSA:
            print_ospf3_lsa_asext_hdr(&(lsa->data.asext_hdr));
            break;
        // LSA-Link
        case LINK_LSA:
            print_ospf3_lsa_link_hdr(&(lsa->data.link_hdr));
            break;
        // LSA-Intra-Area-Prefix
        case INTRA_AREA_PREFIX_LSA:
            print_ospf3_lsa_intra_area_prefix_hdr(&(lsa->data.intra_p_hdr));
            break;
        // Ostatni typy LSA
        default:
            printf("\nThis type of LSA is not supported\n");
            break;
    }

    return (size>0)?size:0;
}
