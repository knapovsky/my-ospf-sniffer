/**
* Projekt do predmetu ISA - OSPFv2, OSPFv3 sniffer s vypsanim databaze
* soubor: 	main.c
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> // getopt
#include <pcap.h>
#include <signal.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
//#include <netinet6/in6.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/ip.h>
//#include <netinet/ether.h>
#include <net/ethernet.h>
#include "sys.h"
#include "const.h"
#include "main.h"
#include "binary.c"
#include "ospfv2.h"
#include "ospfv3.h"
#include "ospfv3_db.h"

// databaze
struct ospf3_db* db = NULL;

/** Funkce je volana, pokud je odposlechnut packet. Packet je dale zpracovan podle typu
*   IP protokolu a OSPF verze. Informace jsou tisknuty na STDOUT.
*@const u_char *packet - ukazatel na zacatek packetu
*/
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){

    // Pocitadlo packetu
    static int count = 0;           // pocitadlo packetu
    static int count_seq = 0;       // pocitadlo OSPF Packetu

    // Zvyseni cisla packetu
    count++;

    // velikost payloadu (obsahu) packetu
    int size_payload;

    // predpokladame, ze odposlechnuty packet je v pameti ulozen souvisle
    // a nastavujeme ukazatele na zacatek dane casti packetu

    // zpracovani ethernetoveho ramce
    const struct ether_header *ethernet;
    ethernet = (struct ether_header*)(packet);

    // Zpracovani IPv6 Packetu
    if(ethernet->ether_type == IPV6){
        const struct ip6_hdr *ipv6;
        ipv6 = (struct ip6_hdr*)(packet + SIZE_ETHERNET);

        // Jedna se o OSPFv3 Packet?
        // stara kontrola podle MULTICAST IP
        //if(check_ipv6_ospf_dst(&(ipv6->ip6_dst))){
        // kontorola podle next header
        if(ipv6->ip6_nxt == 89){
            count_seq++;
            // Tisk cisla packetu
            #ifdef PRINT_PACKET_NUMBER
                printf("\n=======Packet number: %d=======\n", count);
            #endif
            #ifdef PRINT_OSPF_NUMBER
                printf("====OSPF packet number: %d====\n", count_seq);
            #endif
            // oddelovac
            printf("\n");
            #ifdef PRINT_ETHERNET
                // Tisk Ethernetove Hlavicky
                print_ethernet(ethernet);
            #endif
            #ifdef PRINT_IP
                // Tisk IP Hlavicky
                print_ipv6(ipv6);
            #endif

            // ukazatel na hlavicku OSPFv3
            const struct ospf3_header* hdr = (struct ospf3_header*)(packet + SIZE_ETHERNET + SIZE_IPV6);
            print_ospf3_header(hdr);

            // Hello Packet
            if(hdr->type == 1){
                const struct ospf3_hello* hello = (struct ospf3_hello*)((int)hdr + SIZE_OSPF3_HEADER);
                // tisk neighbor ID udava druhy parametr
                print_ospf3_hello(hello, (ntohs(hdr->length) > 36)?1:0 );
            }

            // Database Description Pack
            else if(hdr->type == 2){

                const struct ospf3_db_dscrp_hdr* db_hdr = (struct ospf3_db_dscrp_hdr*)(packet + SIZE_ETHERNET + SIZE_IPV6 + SIZE_OSPF3_HEADER);
                print_ospf3_db_dscrp_hdr(db_hdr);

                // Ukazatel na zacaatek LSA
                const struct ospf3_lsa_hdr* lsa_hdr;
                int offset;
                int counter = 0;

                // Velikost packetu
                size_payload = ntohs(hdr->length);

                // Postupny tisk LSA informaci obsazenych v Datebase Description Packetu
                for(offset = 0; (((int)(offset + sizeof(struct ospf3_db_dscrp_hdr) + SIZE_OSPF3_HEADER)) < size_payload); offset += OSPF3_LSA_HEADER_SIZE){
                    counter++;
                    lsa_hdr = (struct ospf3_lsa_hdr*)((int)db_hdr + sizeof(ospf3_db_dscrp_hdr) + offset);
                    print_ospf3_lsa_hdr(lsa_hdr);

                }
            }
            // Link State Request
            else if(hdr->type == 3){

                const struct ospf3_ls_req_hdr* req_hdr;

                // Velikost Pozadavku
                int req_size = ntohs(hdr->length) - SIZE_OSPF3_HEADER;
                int i = 0;

                // Postupny tisk pozadavku
                while(i < req_size){
                    req_hdr = (struct ospf3_ls_req_hdr*)((int)hdr + SIZE_OSPF3_HEADER + i);
                    print_ospf3_ls_req_hdr(req_hdr);
                    i = i + sizeof(struct ospf3_ls_req_hdr);
                }
            }
            // Link State Update
            else if(hdr->type == 4){
                const struct ospf3_ls_upd_hdr* up_hdr = (struct ospf3_ls_upd_hdr*)(packet + SIZE_ETHERNET + SIZE_IPV6 + sizeof(struct ospf3_header));
                print_ospf3_ls_upd_hdr(up_hdr);

                // Pocet LSA v packetu
                int num_lsa = ntohl(up_hdr->num_lsa);

                // Pomocne promenne a ukazatel na LSA strukturu
                struct ospf3_lsa* lsa = (struct ospf3_lsa*)((int)up_hdr + sizeof(struct ospf3_ls_upd_hdr));
                int offset = 0;
                int begin = (int)lsa;

                // Velikost celeho packetu vcetne OSPF3 Hlavicky
                size_payload = ntohs(hdr->length);

                // Cyklus tisknouci LSA
                while(num_lsa > 0){
                    offset += print_ospf3_lsa(lsa);
                    db = ospf3_db_add_lsa_to_db(db, lsa, hdr->router_id, hdr->area_id, hdr->instance_id);
                    lsa = (struct ospf3_lsa*)(begin + offset);
                    num_lsa--;
                }
            }
            // Link State Acknowledgment
            else if(hdr->type == 5){

                const struct ospf3_lsa_hdr* lsa_hdr;
                int offset;
                int counter = 0;

                size_payload = ntohs(hdr->length);

                // Postupny tisk potvrzeni
                for(offset = 0; ((offset + SIZE_OSPF3_HEADER) < size_payload); offset += OSPF3_LSA_HEADER_SIZE){
                    counter++;
                    lsa_hdr = (struct ospf3_lsa_hdr*)((int)hdr + SIZE_OSPF3_HEADER + offset);
                    print_ospf3_lsa_hdr(lsa_hdr);
                }
            }
        }
        // Nejedna se o OSPFv3 Packet
        else{;}
    }


    // Zpracovani IPv4 Packetu
    else if(ethernet->ether_type == IPV4){
        // velikost ip hlavicky
        int size_ipv4;
        const struct ip *ipv4;
        // ukazatel na zacatel ipv4 packetu
        ipv4 = (struct ip*)(packet + SIZE_ETHERNET);
        size_ipv4 = ipv4->ip_hl*4;
        // spatna velikost packetu
        if(size_ipv4 < 20){
            printf("*Invalid IP header length: %u bytes\n", size_ipv4);
        }

        // test na OSPFv2 Packet a jeho zpracovani
        if(ipv4->ip_p == 89){

            count_seq++;
            // Tisk cisla packetu
            #ifdef PRINT_PACKET_NUMBER
                printf("\n=======Packet number: %d=======\n", count);
            #endif
            #ifdef PRINT_OSPF_NUMBER
                printf("====OSPF packet number: %d====\n", count_seq);
            #endif
            // oddelovac
            printf("\n");
            #ifdef PRINT_ETHERNET
                // Tisk ethernetove hlavicky
                print_ethernet(ethernet);
            #endif
            #ifdef PRINT_IP
                // Tisk IP hlavicky
                print_ipv4(ipv4);
            #endif

            const struct ospf2_header* ospf2_hdr;
            ospf2_hdr = (struct ospf2_header*)(packet +  SIZE_ETHERNET + size_ipv4);
            // ulozeni velikosti ospf2 packetu kvuli vypisu LSA
            size_payload = ntohs(ospf2_hdr->length);
            // tisk ospf2 hlavicky
            print_ospf2_header(ospf2_hdr);

            // pomocne ukazatele na struktury OSPFv2
            const struct ospf2_ls_req_hdr* ospf2_ls_req_hr;
            const struct ospf2_ls_upd_hdr* ospf2_ls_upd_hr;
            #ifdef PRINT_LLS
                const struct ospf2_lls_data_block* data_block;
            #endif
            const struct ospf2_lsa_hdr* ospf2_lsa_hr;
            const struct ospf2_lsa* ospf2_ls;
            // velikost lsa ospf2
            int ospf2_lsa_hdr_len = sizeof(struct ospf2_lsa_hdr);

            // hello
            if(ospf2_hdr->type == 1){
                const struct ospf2_hello* ospf2_hl;
                ospf2_hl = (struct ospf2_hello*)(packet +  SIZE_ETHERNET + size_ipv4 + OSPF2HEADER_LENGTH);
                print_ospf2_hello(ospf2_hl);
                
                #ifdef PRINT_LLS
                    // paket obsahuje lls
                    if(ospf2_hl->opts & B8(00010000)){
                        data_block = (struct ospf2_lls_data_block*)(packet +  SIZE_ETHERNET + size_ipv4 + OSPF2HEADER_LENGTH + sizeof(struct ospf2_hello));
                        print_ospf2_lls_data_block(data_block);
                    }
                #endif
            }

            // database description
            else if(ospf2_hdr->type == 2){
                const struct ospf2_db_dscrp_hdr* ospf2_db_dscrp_hr;
                ospf2_db_dscrp_hr = (struct ospf2_db_dscrp_hdr*)(packet +  SIZE_ETHERNET + size_ipv4 + OSPF2HEADER_LENGTH);
                print_ospf2_db_dscrp_hdr(ospf2_db_dscrp_hr);
                // pomocne promenne
                int counter = 0;
                int offset;
                // velikost packetu
                size_payload = ntohs(ospf2_hdr->length);

                // Postupny tisk LSA informaci
                for(offset = 0;((int) (offset + sizeof(struct ospf2_db_dscrp_hdr) + sizeof(struct ospf2_header))) < size_payload; offset += ospf2_lsa_hdr_len){
                    counter++;
                    ospf2_lsa_hr = (struct ospf2_lsa_hdr*) (packet +  SIZE_ETHERNET + size_ipv4 + OSPF2HEADER_LENGTH + sizeof(struct ospf2_db_dscrp_hdr) + offset);
                    print_ospf2_lsa_hdr(ospf2_lsa_hr);
                }
            }

            // link state request
            else if(ospf2_hdr->type == 3){
                int i = 0;
                int req_size = ntohs(ospf2_hdr->length) - OSPF2HEADER_LENGTH;

                // Postupny tisk pozadavku
                while(i < req_size){
                    ospf2_ls_req_hr = (struct ospf2_ls_req_hdr*)(packet +  SIZE_ETHERNET + size_ipv4 + OSPF2HEADER_LENGTH + i);
                    print_ospf2_ls_req_hdr(ospf2_ls_req_hr);
                    i = i + sizeof(struct ospf2_ls_req_hdr);
                }
            }

            // link state update header
            else if(ospf2_hdr->type == 4){
                // ukazatel na LSA Update Hlavicku
                ospf2_ls_upd_hr = (struct ospf2_ls_upd_hdr*)(packet +  SIZE_ETHERNET + size_ipv4 + OSPF2HEADER_LENGTH);
                // tisk lsa hlavicky
                print_ospf2_ls_upd_hdr(ospf2_ls_upd_hr);
                // ukazatel na lsa
                ospf2_ls = (struct ospf2_lsa*)(packet +  SIZE_ETHERNET + size_ipv4 + OSPF2HEADER_LENGTH + sizeof(struct ospf2_ls_upd_hdr));
                // pocet lsa
                int lsa_num = ntohl(ospf2_ls_upd_hr->num_lsa);
                // pomocna promenna pro odkazovani-se do pameti
                int offset = 0;

                // Postupny tisk LSA
                while(lsa_num > 0){
                    offset += print_ospf2_lsa(ospf2_ls, packet, size_ipv4);
                    ospf2_ls = (struct ospf2_lsa*)(packet +  SIZE_ETHERNET + size_ipv4 + OSPF2HEADER_LENGTH + sizeof(struct ospf2_ls_upd_hdr) + offset);
                    lsa_num--;
                }

            }
            else if(ospf2_hdr->type == 5){

                // pomocne promenne
                int counter = 0;
                int offset;

                // velikost packetu
                size_payload = ntohs(ospf2_hdr->length);

                // postupny tisk potvrzeni
                for(offset = 0;((int) (offset + sizeof(struct ospf2_header))) < size_payload; offset += ospf2_lsa_hdr_len){
                    counter++;
                    ospf2_lsa_hr = (struct ospf2_lsa_hdr*) (packet +  SIZE_ETHERNET + size_ipv4 + OSPF2HEADER_LENGTH  + offset);
                    print_ospf2_lsa_hdr(ospf2_lsa_hr);
                }
            }
            else{
                // Neplatny typ OSPFv2 packetu
                printf("*Wrong OSPFv2 Type %d", ospf2_hdr->type);
            }
        }
        // Nejedna se o OSPFv2 Packet
        else{
            ;
        }
    }
    // Nejedna se o IPv4 nebo IPv6 Protokol
    else{
        ;
    }

    return;
}

// Obsluha signalu SIGINT
void terminate(){
    
    // tisk OSPFv3 LSA Databaze
    print_ospf3_db(db);
    // odstraneni OSPFv3 LSA Databaze z pameti
    free_ospf3_db(db);

    exit(0);

}

// OSPFv2 a OSPFv3 Sniffer s vypisem OSPFv3 LSA Topologie po zaslani signalu SIGINT
int main(int argc, char *argv[])
{
    char *dev = NULL;               // zarizeni pro odposlech
    char errbuf[PCAP_ERRBUF_SIZE];  // chybovy retezec
    pcap_t *handle;                 // handle zarizeni pro odposlech
    struct bpf_program fp;          // kompilovany vyraz
    char filter_exp[] = FILTER_EXP; // retezec pro filtr
    bpf_u_int32 mask;               // sitova maska naslouchajiciho zarizeni
    bpf_u_int32 net;                // ip adresa naslouchajiciho zarizeni

    // funkce spustena po zaslani signalu ukonceni
    signal(SIGINT, &terminate);

    if(argc > 3 || argc == 1){
        printf("Too many or few arguments. Use \'.\\%s -h\' for help.\n", APP_NAME);
        return(EXIT_FAILURE);
    }

    char c;
    while((c = getopt(argc, argv, "hi:")) != -1){
        switch(c){
            case 'h':
                print_help();
                return(EXIT_SUCCESS);
                break;
            case 'i':
                dev = optarg;
                #ifdef DEBUG
                    printf("dev: %s", dev);
                #endif
                break;
            default:
                print_help();
                return(EXIT_FAILURE);
                break;
        }
    }

    /* automaticke otevreni defaultniho zarizeni - neni v zadani
    else{
        dev = pcap_lookupdev(errbuf);
        if(dev == NULL){
            fprintf(ERROUT, "Couldn't find default device: %s\n", errbuf);
            return(EXIT_FAILURE);
        }
    }*/

    // zjisteni ip adresy a masky zarizeni - musime ji znat pro kompilaci filtru
    if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1){
        #ifdef DEBUG
            fprintf(ERROUT, "Can't get netmask for device %s, %s\n", dev, errbuf);
        #endif
        net = 0;
        mask = 0;
        //return ERRDEV;
    }

    #ifdef DEBUG
        printf("Device: %s\n", dev);
    #endif

    #ifdef DEBUG
        printf("Device %s succesfully opened.\n", dev);
    #endif

    // otevreni zarizeni dev do promiskuitniho modu s timeoutem 1000ms
    handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    if(handle == NULL){
        fprintf(ERROUT, "Couldn't open device %s: %s\n", dev, errbuf);
        return(EXIT_FAILURE);
    }

    // overeni, zda zachytavame na Ethernetovem zarizeni
    if(pcap_datalink(handle) != DLT_EN10MB){
        fprintf(ERROUT, "%s is not an Ethernet interface\n", dev);
        exit(EXIT_FAILURE);
    }

    // kompilace vyrazu pro filtr
    if(pcap_compile(handle, &fp, filter_exp, 0, net) == -1){
        fprintf(ERROUT, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(EXIT_FAILURE);
    }

    // aplikace filtru
    if(pcap_setfilter(handle, &fp) == -1){
        fprintf(ERROUT, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(EXIT_FAILURE);
    }

    //ospf3_db_init(db);
    // odposlech packetu
    pcap_loop(handle, NUMPACKETS, got_packet, NULL);

    // ukonceni odposlechu a uzavreni sezeni
    pcap_freecode(&fp);
    pcap_close(handle);

    return(EXIT_SUCCESS);
}
