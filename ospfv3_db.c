/**
* Projekt do predmetu ISA - OSPFv2, OSPFv3 sniffer s vypsanim databaze
* soubor: 	ospfv3_db.c
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
#include "ospfv3_db.h"
#include "sys.h"
#include "const.h"

// Inicializace OSPFv3 Databaze
void ospf3_db_init(struct ospf3_db* db){

    db->router_id = 0;
    db->instance_list = NULL;
    db->next = NULL;

    return;
}

// Inicializuje OSPFv3 Area Seznamu
void ospf3_db_area_init(struct ospf3_db_area* area){

    area->area_id = 0;
    area->rtr_ls = NULL;
    area->net_ls = NULL;
    area->ia_p_ls = NULL;
    area->ia_rtr_ls = NULL;
    area->asext_ls = NULL;
    area->link_ls = NULL;
    area->intra_p_ls = NULL;
    // ukazatel na dalsi databazi
    area->next = NULL;

    return;
}

// Inicializace OSPFv3 Instance Seznamu
void ospf3_db_instance_init(struct ospf3_db_instance* instance){

    instance->instance_id = 0;
    instance->area_list = NULL;
    instance->next = NULL;

    return;
}

// Inicializace OSPFv3 Item Seznamu
void ospf3_db_item_init(struct ospf3_db_item* item){

    item->lsa = NULL;
    item->next = NULL;

}

// Pridava novou databazi
struct ospf3_db* ospf3_db_add_db (struct ospf3_db* db){

    // jiz existujici databaze
    if(db != NULL){
        struct ospf3_db* last_item;
        struct ospf3_db* iterator = db;

        while(iterator != NULL){
            last_item = iterator;
            iterator = last_item->next;
        }

        struct ospf3_db* new_item = (struct ospf3_db*)malloc(sizeof(struct ospf3_db));
        ospf3_db_init(new_item);
        last_item->next = new_item;
        return new_item;
    }
    // prazdna databaze
    else{
        struct ospf3_db* new_item = (struct ospf3_db*)malloc(sizeof(struct ospf3_db));
        ospf3_db_init(new_item);
        db = new_item;
        return new_item;
    }

}

// Pridava polozku do instance seznamu
struct ospf3_db_instance* ospf3_db_add_instance(struct ospf3_db_instance* instance){

    // jiz existujici seznam
    if(instance != NULL){
        struct ospf3_db_instance* last_item;
        struct ospf3_db_instance* iterator = instance;

        while(iterator != NULL){
            last_item = iterator;
            iterator = last_item->next;
        }

        struct ospf3_db_instance* new_item = (struct ospf3_db_instance*)malloc(sizeof(struct ospf3_db_instance));
        ospf3_db_instance_init(new_item);
        last_item->next = new_item;
        return new_item;
    }
    // prazdny seznam
    else{
        struct ospf3_db_instance* new_item = (struct ospf3_db_instance*)malloc(sizeof(struct ospf3_db_instance));
        ospf3_db_instance_init(new_item);
        instance = new_item;
        return new_item;
    }

}

// Pridava polozku do area seznamu
struct ospf3_db_area* ospf3_db_add_area(struct ospf3_db_area* area){

    // jiz existujici seznam
    if(area != NULL){
        struct ospf3_db_area* last_item;
        struct ospf3_db_area* iterator = area;

        // hledani posledniho prvku
        while(iterator != NULL){
            last_item = iterator;
            iterator = last_item->next;
        }

        // vytvoreni noveho prvku
        struct ospf3_db_area* new_item = (struct ospf3_db_area*)malloc(sizeof(struct ospf3_db_area));
        ospf3_db_area_init(new_item);
        last_item->next = new_item;
        return new_item;
    }
    // prazdny seznam
    else{
        // vytvoreni noveho prvku
        struct ospf3_db_area* new_item = (struct ospf3_db_area*)malloc(sizeof(struct ospf3_db_area));
        ospf3_db_area_init(new_item);
        area = new_item;
        return new_item;
    }

}

// Pridava polozku do databaze
struct ospf3_db_item* ospf3_db_add_item (struct ospf3_db_item* item, struct ospf3_lsa* lsa){

    if(item != NULL){
        struct ospf3_db_item* last_item;
        struct ospf3_db_item* iterator = item;

        // nalezeni posledniho prvku
        while(iterator != NULL){
            last_item = iterator;
            iterator = last_item->next;
        }

        // vytvoreni noveho prvku
        struct ospf3_db_item* new_item = (struct ospf3_db_item*)malloc(sizeof(struct ospf3_db_item));
        // kopirovani LSA
        new_item->lsa = ospf3_db_add_lsa_to_item(lsa);
        new_item->next = NULL;
        last_item->next = new_item;
        // vraci se ukazatel na seznam - ne na danou polozku seznamu
        return item;
    }
    else{
        // vytvoreni noveho prvku
        struct ospf3_db_item* new_item = (struct ospf3_db_item*)malloc(sizeof(struct ospf3_db_item));
        // kopirovani LSA
        new_item->lsa = ospf3_db_add_lsa_to_item(lsa);
        new_item->next = NULL;
        //item = new_item;
        return new_item;
    }

}


// Kopiruje LSA do databaze
struct ospf3_lsa* ospf3_db_add_lsa_to_item(struct ospf3_lsa* lsa){

    // alokace LSA struktury a jeji naplneni prijatym LSA
    struct ospf3_lsa* new_lsa = (struct ospf3_lsa*)malloc(ntohs(lsa->hdr.len));
    // puvodni kopirovani cele struktury LSA
    //memcpy((void*)new_lsa, (void*)lsa, ntohs(lsa->hdr.len));
    
    // kopirovani LSA po bytu - kvuli endianu
    u_int8_t* new_lsa_iterator = (u_int8_t*)(new_lsa);
    u_int8_t* lsa_iterator = (u_int8_t*)(lsa);
    int i = ntohs(lsa->hdr.len);
    while(i > 0){
        memcpy(new_lsa_iterator, lsa_iterator, sizeof(u_int8_t));
        // posun iteratoru
        new_lsa_iterator = (u_int8_t*)((int)new_lsa_iterator + sizeof(u_int8_t));
        lsa_iterator = (u_int8_t*)((int)lsa_iterator + sizeof(u_int8_t));
        // odecteni bytu z celkove velikosti
        i--;
    }

    return new_lsa;
}

// Tiskne dane polozky z databaze
void print_ospf3_db_item (const struct ospf3_db_item* item){

    // pomocne retezce pro prevod ip adres
    char ip[BUFFER_LENGTH];
    char id[BUFFER_LENGTH];
    char ref_id[BUFFER_LENGTH];
    char ip6[INET6_ADDRSTRLEN];
    char dst_rtr_id[BUFFER_LENGTH];
    // pomocne pocitadlo
    int i = 0;
    // pomocna promenna
    int x;

    if(item == NULL) return;
    else{
        const struct ospf3_db_item* iterator = item;
        while(iterator != NULL){

            int type = ntohs(iterator->lsa->hdr.type);
            // pridat lsa do nove databaze
            switch(type){

                // LSA-Router
                case ROUTER_LSA:

                    // zjisteni poctu spoju
                    x = ntohs(iterator->lsa->hdr.len) - sizeof(struct ospf3_lsa_hdr) - sizeof(struct ospf3_lsa_rtr_hdr);
                    i = x / sizeof(struct ospf3_lsa_rtr);
                    ipv4_to_str(ip, ntohl(iterator->lsa->hdr.adv_rtr));

                    // vypis informaci
                    // ADV Router   Age     Seq#        Fragment ID Link count  Bits
                    printf("%s\t\t%d\t\t0x%X\t0\t\t\t%d\t\t\t", ip, ntohs(iterator->lsa->hdr.age), ntohl(iterator->lsa->hdr.seq_num), i);
                    // vypis Bits
                    if(i > 0) printf("0x%X\n", ((ntohl(iterator->lsa->data.rtr_hdr.opts) & 0xff000000) >> 24));
                    else printf("None\n");
                    break;

                // LSA-Network
                case NETWORK_LSA:

                    // zjisteni poctu spoju
                    x = ntohs(iterator->lsa->hdr.len) - sizeof(struct ospf3_lsa_hdr) - sizeof(struct ospf3_lsa_net_hdr);
                    i = x / sizeof(struct ospf3_lsa_net);

                    // vypis informaci
                    // ADV Router   Age     Seq#        Link ID Rtr count
                    ipv4_to_str(ip, ntohl(iterator->lsa->hdr.adv_rtr));
                    ipv4_to_str(id, ntohl(iterator->lsa->hdr.ls_id));
                    printf("%s\t\t%d\t\t0x%X\t%s\t%d\n", ip, ntohs(iterator->lsa->hdr.age), ntohl(iterator->lsa->hdr.seq_num), id, i);
                    break;

                // LSA-Intra-Area-Prefix - DONE
                case IA_PREFIX_LSA:

                    // prevod ip na retezce
                    ipv4_to_str(id, ntohl(iterator->lsa->hdr.ls_id));
                    ipv4_to_str(ip, ntohl(iterator->lsa->hdr.adv_rtr));

                    // vypis informaci
                    // ADV Router  Age     Seq#        Prefix
                    printf("%s\t\t%d\t\t0x%X\t", ip, ntohs(iterator->lsa->hdr.age), ntohl(iterator->lsa->hdr.seq_num)); // done
                    print_address_prefix((char*)((int)(&(iterator->lsa->data.ia_p_hdr)) + sizeof(struct ospf3_lsa_inter_area_prefix_hdr)), iterator->lsa->data.ia_p_hdr.p_len);

                    // pocet bitu prefixu
                    printf("/%d\n", iterator->lsa->data.ia_p_hdr.p_len);
                    break;

                // LSA-Intra-Area-Router
                case IA_RTR_LSA:

                    // prevod ip na retezce
                    ipv4_to_str(ip, ntohl(iterator->lsa->hdr.adv_rtr));
                    ipv4_to_str(id, ntohl(iterator->lsa->hdr.ls_id));
                    ipv4_to_str(dst_rtr_id, ntohl(iterator->lsa->data.ia_rtr.dst_rtr_id));

                    // vypis informaci
                    // ADV Router	Age		Seq#		Link ID	Dest RtrID
                    printf("%s\t\t%d\t\t0x%X\t%s\t%s\n", ip, ntohs(iterator->lsa->hdr.age), ntohl(iterator->lsa->hdr.seq_num), id, dst_rtr_id);
                    break;

                // LSA-AS-External
                case ASEXT_LSA:

                    // zjisteni poctu spoju
                    x = ntohs(iterator->lsa->hdr.len) - sizeof(struct ospf3_lsa_hdr) - sizeof(struct ospf3_lsa_asext_hdr);
                    i = x / sizeof(struct ospf3_lsa_asext_hdr);

                    // prevod ip na retezce
                    ipv4_to_str(ip, ntohl(iterator->lsa->hdr.adv_rtr));
                    ipv4_to_str(id, ntohl(iterator->lsa->hdr.ls_id));

                    // vypis informaci
                    // ADV Router   Age     Seq#        Link ID Rtr count
                    printf("%s\t\t%d\t\t0x%X\t%s\t%d\n", ip, ntohs(iterator->lsa->hdr.age), ntohl(iterator->lsa->hdr.seq_num), id, i);
                    break;

                // LSA-Link
                case LINK_LSA:

                    // prevod ip na retezce
                    ipv6_to_str_unexpanded(ip6, (struct in6_addr*)(&(iterator->lsa->data.link_hdr.addr)));
                    ipv4_to_str(id, ntohl(iterator->lsa->hdr.ls_id));
                    ipv4_to_str(ip, ntohl(iterator->lsa->hdr.adv_rtr));

                    // vypis informaci
                    // ADV Router   Age     Seq#        Link ID Interface
                    printf("%s\t\t%d\t\t0x%X\t%s\t%s\n", ip, ntohs(iterator->lsa->hdr.age), ntohl(iterator->lsa->hdr.seq_num), id, ip6);
                    break;

                // LSA-Intra-Area-Prefix
                case INTRA_AREA_PREFIX_LSA:

                    // prevod ip na retezce
                    ipv4_to_str(id, ntohl(iterator->lsa->hdr.ls_id));
                    ipv4_to_str(ip, ntohl(iterator->lsa->hdr.adv_rtr));
                    ipv4_to_str(ref_id, ntohl(iterator->lsa->data.intra_p_hdr.ref_ls_id));

                    // vypis informaci
                    // ADV Router   Age     Seq#        Link ID Ref-lstype  Ref-LSID
                    printf("%s\t\t%d\t\t0x%X\t%s\t0x%X\t\t%s\n", ip, ntohs(iterator->lsa->hdr.age), ntohl(iterator->lsa->hdr.seq_num), id, ntohs(iterator->lsa->data.intra_p_hdr.type), ref_id);
                    break;

                // Ostatni typy LSA
                default:
                    break;

            } // switch

            // posud na dalsi lsa
            iterator = iterator->next;

        } // while
    } // else

    return;

}

// Tiskne OSPFv3 LSA Databazi
void print_ospf3_db (struct ospf3_db* db){

    if(db == NULL) return;
    else{
        char id[BUFFER_LENGTH];
        struct ospf3_db* iterator = db;
        struct ospf3_db_instance* i_iterator;
        struct ospf3_db_area* a_iterator;

        printf("\n==========OSPFv3 Database==========\n\n");

        // iterace databazemi - Router ID
        while(iterator != NULL){

            // iterace instancemi - Instance ID
            i_iterator = iterator->instance_list;
            while(i_iterator != NULL){

                // iterace area - Area ID
                a_iterator = i_iterator->area_list;
                while(a_iterator != NULL){
                    
                    // pokud je seznam LSA prazdny, netiskne se hlavicka
                    ipv4_to_str(id, ntohl(iterator->router_id));
                    
                    // tisk nazvu databaze
                    printf("\t\tOSPFv3 Router with ID (%s) (Process ID %d)\n\n", id, ntohl(i_iterator->instance_id));

                    // Router-LSA
                    if(a_iterator->rtr_ls != NULL){
                        printf("Router Link States (Area %d)\n\n", ntohl(a_iterator->area_id));
                        printf("ADV Router\tAge\t\tSeq#\t\tFragment ID\tLink count\tBits\n"); // done
                        print_ospf3_db_item(a_iterator->rtr_ls);
                        printf("\n");
                    }

                    // Network-LSA
                    if(a_iterator->net_ls){
                        printf("Net Link States (Area %d)\n\n", ntohl(a_iterator->area_id));
                        printf("ADV Router\tAge\t\tSeq#\t\tLink ID\tRtr count\n");
                        print_ospf3_db_item(a_iterator->net_ls);
                        printf("\n");
                    }

                    // Inter-Area-Prefix-LSA
                    if(a_iterator->ia_p_ls){
                        printf("Inter Area Prefix Link States (Area %d)\n\n", ntohl(a_iterator->area_id));
                        printf("ADV Router\tAge\t\tSeq#\t\tPrefix\n"); // done
                        print_ospf3_db_item(a_iterator->ia_p_ls);
                        printf("\n");
                    }

                    // Inter-Area-Router-LSA
                    if(a_iterator->ia_rtr_ls){
                        printf("Inter Area Router Link States (Area %d)\n\n", ntohl(a_iterator->area_id));
                        printf("ADV Router\tAge\t\tSeq#\t\tLink ID\tDest RtrID\n"); // done
                        print_ospf3_db_item(a_iterator->ia_rtr_ls);
                        printf("\n");
                    }

                    // AS-External-LSA
                    if(a_iterator->asext_ls){
                        printf("AS-External Link States (Area %d)\n\n", ntohl(a_iterator->area_id));
                        printf("ADV Router\tAge\t\tSeq#\t\tLink ID\tRtr count\n");
                        print_ospf3_db_item(a_iterator->asext_ls);
                        printf("\n");
                    }

                    // Link-LSA
                    if(a_iterator->link_ls){
                        printf("Link (Type-8) Link States (Area %d)\n\n", ntohl(a_iterator->area_id));
                        printf("ADV Router\tAge\t\tSeq#\t\tLink ID\tInterface\n"); // done
                        print_ospf3_db_item(a_iterator->link_ls);
                        printf("\n");
                    }

                    // Intra-Area-Prefix-LSA
                    if(a_iterator->intra_p_ls){
                        printf("Intra Area Prefix Link States (Area %d)\n\n", ntohl(a_iterator->area_id));
                        printf("ADV Router\tAge\t\tSeq#\t\tLink ID\tRef-lstype\tRef-LSID\n"); // done
                        print_ospf3_db_item(a_iterator->intra_p_ls);
                        printf("\n");
                    }
                    // posun na dalsi prvek
                    a_iterator = a_iterator->next;
                } // Area ID
                // posun na dalsi prvek
                i_iterator = i_iterator->next;
            } // Instance ID
            // posun na dalsi prvek
            iterator = iterator->next;
        } // Router ID
    } // else

    return;

}

// Rusi dane polozky databaze v pameti
int free_ospf3_db_item (struct ospf3_db_item* item){

    if(item == NULL) return EXIT_FAILURE;
    if(item->next == NULL){
        free(item->lsa);
        free(item);
        return EXIT_SUCCESS;
    }
    else{
        free_ospf3_db_item(item->next);
        free(item->lsa);
        free(item);
        return EXIT_SUCCESS;
    }

}

// Rusi seznam area
int free_ospf3_db_area (struct ospf3_db_area* area) {

    if(area == NULL) return EXIT_FAILURE;
    // posledni prvek seznamu
    if(area->next == NULL){
        free_ospf3_db_item(area->rtr_ls);
        free_ospf3_db_item(area->net_ls);
        free_ospf3_db_item(area->ia_p_ls);
        free_ospf3_db_item(area->ia_rtr_ls);
        free_ospf3_db_item(area->asext_ls);
        free_ospf3_db_item(area->link_ls);
        free_ospf3_db_item(area->intra_p_ls);
        free(area);
        return EXIT_SUCCESS;
    }
    // zanoreni
    else{
        free_ospf3_db_area(area->next);
        free(area);
        return EXIT_SUCCESS;
    }

}

// Rusi seznam instanci
int free_ospf3_db_instance (struct ospf3_db_instance* instance){

    if(instance == NULL) return EXIT_FAILURE;
    // posledni prvek
    if(instance->next == NULL){
        free_ospf3_db_area(instance->area_list);
        free(instance);
        return EXIT_SUCCESS;
    }
    // zanoreni
    else{
        free_ospf3_db_instance(instance->next);
        free(instance);
        return EXIT_SUCCESS;
    }

}

// Rusi danou databazi
int free_ospf3_db (struct ospf3_db* db){

    if(db == NULL) return EXIT_FAILURE;
    if(db->next == NULL){
        free_ospf3_db_instance(db->instance_list);
        free(db);
        return EXIT_SUCCESS;
    }
    else{
        free_ospf3_db(db->next);
        free(db);
        return EXIT_SUCCESS;
    }

}

// Pridava LSA do databaze
struct ospf3_db* ospf3_db_add_lsa_to_db (struct ospf3_db* db, struct ospf3_lsa* lsa, u_int32_t rtr_id, u_int32_t area_id, u_int32_t instance_id) {

    // pocitadlo lsa v databazi
    static int lsa_num = 0;
    lsa_num++;

    // osetreni prazdneho LSA
    if(lsa == NULL) return db;

    // typ lsa
    int type = ntohs(lsa->hdr.type);

    // UROVEN DATABAZE

    // prazdna databaze - vytvoreni nove db
    if(db == NULL) {
        db = ospf3_db_add_db(db);
        db->router_id = rtr_id;
    }

    // nalezeni stravne databaze
    struct ospf3_db* iterator = db;
    while((iterator != NULL) && (iterator->router_id != rtr_id)){
        iterator = iterator->next;
    }

    // polozka nebyla nalezena - vytvorime novou
    if(iterator == NULL){
        iterator = ospf3_db_add_db(db);
        iterator->router_id = rtr_id;
    }

    // UROVEN INSTANCE

    // instance list je prazdny - vytvorime novy
    if(iterator->instance_list == NULL){
        iterator->instance_list = ospf3_db_add_instance(iterator->instance_list);
        iterator->instance_list->instance_id = instance_id;
    }

    // nalezeni spravne instance
    struct ospf3_db_instance* i_iterator = iterator->instance_list;
    while((i_iterator != NULL) && (i_iterator->instance_id != instance_id)){
        i_iterator = i_iterator->next;
    }

    // instance nebyla nalezena - pridame novou
    if(i_iterator == NULL){
        i_iterator = ospf3_db_add_instance(iterator->instance_list);
        i_iterator->instance_id = instance_id;
    }

    // UROVEN AREA

    // area list je prazdny - pridame novy
    if(i_iterator->area_list == NULL){
        i_iterator->area_list = ospf3_db_add_area(i_iterator->area_list);
        i_iterator->area_list->area_id = area_id;
    }

    // nalezeni spravne Area
    struct ospf3_db_area* a_iterator = i_iterator->area_list;
    while((a_iterator != NULL) && (a_iterator->area_id != area_id)){
        a_iterator = a_iterator->next;
    }

    // area nebyla nalezena - pridame novou
    if(a_iterator == NULL){
        a_iterator = ospf3_db_add_area(i_iterator->area_list);
        a_iterator->area_id = area_id;
    }

    // pridat lsa do nove databaze
    switch(type){
            // LSA-Router
        case ROUTER_LSA:
            a_iterator->rtr_ls = ospf3_db_add_item(a_iterator->rtr_ls, lsa);
            break;
        // LSA-Network
        case NETWORK_LSA:
            a_iterator->net_ls = ospf3_db_add_item(a_iterator->net_ls, lsa);
            break;
        // LSA-Intra-Area-Prefix
        case IA_PREFIX_LSA:
            a_iterator->ia_p_ls = ospf3_db_add_item(a_iterator->ia_p_ls, lsa);
            break;
        // LSA-Intra-Area-Router
        case IA_RTR_LSA:
            a_iterator->ia_rtr_ls = ospf3_db_add_item(a_iterator->ia_rtr_ls, lsa);
            break;
        // LSA-AS-External
        case ASEXT_LSA:
            a_iterator->asext_ls = ospf3_db_add_item(a_iterator->asext_ls, lsa);
            break;
        // LSA-Link
        case LINK_LSA:
            a_iterator->link_ls = ospf3_db_add_item(a_iterator->link_ls, lsa);
            break;
        // LSA-Intra-Area-Prefix
        case INTRA_AREA_PREFIX_LSA:
            a_iterator->intra_p_ls = ospf3_db_add_item(a_iterator->intra_p_ls, lsa);
            break;
        // Ostatni typy LSA
        default:
            break;
    }
    
    // navrat ukazatele na databazi
    return db;

}
