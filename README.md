# My OSPF Sniffer

V programu nebyla implementovana zadna rozsireni, vypis odposlechnutych informaci ma format odpovidajici programu wireshark a vypis databaze LSA odpovida formatu na zarizenich firmy Cisco.

Program je spustitelny na operacnich systemech FreeBSD a Linux. Pro preklad na operacnim systemu FreeBSD pouzijte GNU Make bez parametru.

```
> gmake
```

Pro preklad na operacnim systemu Linux je potreba dodat parametr linux.

```
> make linux
```

Pro dalsi nastaveni chovani programu je mozne zmenit definice v hlavickovem souboru const.h. Popis definic je mozne najit v dokumentaci.

@z tohoto souboru byla pro kompatibilitu odstranena diakritika

![ArticleTitle](http://images.knapovsky.com/ospf-full-topology.jpg)

## Úvod

Cílem projektu bylo implementovat aplikaci pro odposlech OSPF zpráv podporující IPv4 a IPv6 LSA topologické informace a po ukončení tohoto programu i exportér OSPFv3 LSA topologických informací. Aplikace je implementována v programovacím jazyku C pro prostředí FreeBSD/Linux.

## Směrovací protokoly

Směrovací protokoly zahrnují sadu procesů, datových struktur, algoritmů a zpráv, které slouží k přenosu informací mezi směrovači. Umožňují tak směrovači se autonomně rozhodnout o tom, na který výstup odešle zprávy, které nejsou určeny pro zařízení k němu přímo připojená, ale pro zařízení, ke kterým pomocí směrovacích protokolů získal cestu.

Směrovací protokoly se rozdělují na Distance Vector a Link State protokoly. Distance Vector protokoly jsou vhodné pro menší sítě, ve kterých není potřeba znát síťovou topologii. Pro výpočet nejlepší cesty používají Bellman-Fordův algoritmus a mezi typické zástupce patří protokoly RIPv1, RIPv2, IGRP, EIGRP. Oproti tomu Link State protokoly vytváří kompletní pohled na topologii sítě a umožňují tak efektivnější směrování v rozsáhlejších sítích.

### OSPF

Open Shortest Path First, neboli zkráceně OSPF je Link State směrovací protokol využívající Dijkstrova algoritmu stejného názvu. Byl vyvinut jako náhrada protokolu RIP, zahrnuje koncept oblastí a pomocí výše zmíněného algoritmu vytváří kompletní topologii sítě. To mu umožňuje nasazení ve větších, hierarchicky strukturovaných sítích s možností pozdějšího růstu.

Protokol za svou dobu prošel několika inovacemi. Původní OSPFv1 byl pouze experimentální, ktežto OSPFv2, který byl vyvinut Johnem Moyem v roce 1991 se dočkal okamžitého nasazení na poli počítačových sítí. Nejnovější revize OSPFv3 zahrnuje podporu IPv6 a zjednodušuje některé ze zpráv, které používá jeho předchůdce.

#### Typy zpráv protokolu OSPF

Následující tabulka uvádí typy zpráv protokolu OSPFv2 a OSPFv3.

<table><colgroup><col> <col> <col></colgroup><tbody><tr><td><div class="layoutArea"><div class="column"><div></div>Kód zprávy<div></div></div></div></td><td><div class="layoutArea"><div class="column"><div></div>Typ zprávy<div></div></div></div></td><td><div class="layoutArea"><div class="column"><div></div>Popis<div></div></div></div></td></tr><tr><td><div class="layoutArea"><div class="column"><div></div>0x01<div></div></div></div></td><td><div class="layoutArea"><div class="column"><div></div>Hello<div></div></div></div></td><td><div class="layoutArea"><div class="column"><div></div>Slouží k objevení sousedů a navázání spojení mezi směrovači.<div></div></div></div></td></tr><tr><td><div class="layoutArea"><div class="column"><div></div>0x02<div></div></div></div></td><td><div class="layoutArea"><div class="column"><div></div>Database Description<div></div></div></div></td><td><div class="layoutArea"><div class="column"><div></div>Obsahuje zkracený seznam databáze směrovacích informací.<div></div></div></div></td></tr><tr><td><div class="layoutArea"><div class="column"><div></div>0x03<div></div></div></div></td><td><div class="layoutArea"><div class="column"><div></div>Link-State Request<div></div></div></div></td><td><div class="layoutArea"><div class="column"><div></div>Požadavek na směrovací informace.<div></div></div></div></td></tr><tr><td><div class="layoutArea"><div class="column"><div></div>0x04<div></div></div></div></td><td><div class="layoutArea"><div class="column"><div></div>Link-State Update<div></div></div></div></td><td><div class="layoutArea"><div class="column"><div></div>Odpověď na požadavek obsahující směrovací informace.<div></div></div></div></td></tr><tr><td><div class="layoutArea"><div class="column"><div></div>0x05<div></div></div></div></td><td><div class="layoutArea"><div class="column"><div></div>Link-State Acknowledgment<div></div></div></div></td><td><div class="layoutArea"><div class="column"><div></div>Potvrzení příjmu směrovacích informací.<div></div></div></div></td></tr></tbody></table>

#### Databázové informace

Informace o databázi směrovače jsou distribuovány ve formě zpráv Link-State Advertisments (LSA), které jsou obsaženy ve zprávě typu Link-State Update. Zde jsou již typy zpráv různých revizí více odlišné. V následující tabulce jsou uvedeny typy zpráv a jejich popis pro OSPFv3.

<table><colgroup><col> <col> <col></colgroup><tbody><tr><td><div class="layoutArea"><div class="column"><div></div>Kód zprávy<div></div></div></div></td><td><div class="layoutArea"><div class="column"><div></div>Typ zprávy<div></div></div></div></td><td><div class="layoutArea"><div class="column"><div></div>Popis<div></div></div></div></td></tr><tr><td><div class="layoutArea"><div class="column"><div></div>0x2001<div></div></div></div></td><td><div class="layoutArea"><div class="column"><div></div>Router-LSA<div></div></div></div></td><td><div class="layoutArea"><div class="column"><div></div>Popis stavu a metriky rozhranní směrovače.<div></div></div></div></td></tr><tr><td><div class="layoutArea"><div class="column"><div></div>0x2002<div></div></div></div></td><td><div class="layoutArea"><div class="column"><div></div>Network-LSA<div></div></div></div></td><td><div class="layoutArea"><div class="column"><div></div>Popis všech směrovaču připojených k danému spoji.<div></div></div></div></td></tr><tr><td><div class="layoutArea"><div class="column"><div></div>0x2003<div></div></div></div></td><td><div class="layoutArea"><div class="column"><div></div>Inter-Area-Prefix-LSA<div></div></div></div></td><td><div class="layoutArea"><div class="column"><div></div>Popis cest a prefixů v jiných oblastech.<div></div></div></div></td></tr><tr><td><div class="layoutArea"><div class="column"><div></div>0x2004<div></div></div></div></td><td><div class="layoutArea"><div class="column"><div></div>Inter-Area-Router-LSA<div></div></div></div></td><td><div class="layoutArea"><div class="column"><div></div>Původcem těchto zpráv jsou hraniční směrovače informující ostatní hraniční směrovače v jiných oblastech o vnitřních cestách.<div></div></div></div></td></tr><tr><td><div class="layoutArea"><div class="column"><div></div>0x4005<div></div></div></div></td><td><div class="layoutArea"><div class="column"><div></div>AS-External-LSA<div></div></div></div></td><td><div class="layoutArea"><div class="column"><div></div>Slouží pro popis implicitní cesty.<div></div></div></div></td></tr><tr><td><div class="layoutArea"><div class="column"><div></div>0x2006<div></div></div></div></td><td><div class="layoutArea"><div class="column"><div></div>Neschváleno<div></div></div></div></td><td></td></tr><tr><td><div class="layoutArea"><div class="column"><div></div>0x2007<div></div></div></div></td><td><div class="layoutArea"><div class="column"><div></div>NSSA-LSA<div></div></div></div></td><td><div class="layoutArea"><div class="column"><div></div>Vysílány hraničními směrovači k popisu vzdálených lokací mimo autonomní systém.<div></div></div></div></td></tr><tr><td><div class="layoutArea"><div class="column"><div></div>0x0008<div></div></div></div></td><td><div class="layoutArea"><div class="column"><div></div>Link-LSA<div></div></div></div></td><td><div class="layoutArea"><div class="column"><div></div>Pro každý fyzický spoj je generána zpráva tohoto typu, která poskytuje informace směrovačům na daném spoji o adresách typu link-local a prefixech.<div></div></div></div></td></tr><tr><td><div class="layoutArea"><div class="column"><div></div>0x2009<div></div></div></div></td><td><div class="layoutArea"><div class="column"><div></div>Intra-Area-Prefix-LSA<div></div></div></div></td><td><div class="layoutArea"><div class="column"><div></div>Určeno pro šíření informací o prefixech spojených s místní adresou směrovače, síťovým segmentem, nebo připojeným tranzitním síťovým segmentem.<div></div></div></div></td></tr></tbody></table>

## Popis programu

Program zachytává zprávy na naslouchaném ethernetovém rozhranní v promiskuitním módu a vypisuje informace v nich obsažené. Tyto informace zahrnují výpis hlavičky ethernetového rámce, výpis hlavičky IP packetu a dále hlavičku, typ zprávy popř. další doplňující informace OSPF ve zprávě obsažené. Po ukončení programu zasláním signálu SIGINT je programem vypsána OSPFv3 topologie z odposlechnutých zpráv.

### Spuštění

Pro spuštění je potřeba programu pomocí parametru zadat rozhranní, na kterém bude naslouchat pomocí přepínače –i následujícím způsobem :

./myospfsniffer –i eth1
,kde eth1 je rozhranní, na kterém se bude naslouchat. Pro výpis nápovědy je možné použít přepínač –h.

### Implementace

#### Moduly

Program je rozčleněn do několika modulů :

- **sys** - obsahuje funkce pro tisk nápovědy, ethernetových a ip hlaviček a dále funkce pro tisk IPv4 a IPv6 adres a jejich prefixů
- **const** - definice kostant použitých v programu
- **binary** - makro pro převod čísla z binární reprezentace do reprezentace programovacího jazyka C
- **ospfv2** - struktury a funkce pro výpis OSPFv2 informací
- **ospfv3** - struktury a funkce pro výpis OSPFv3 informací
- **ospfv3\_db** - struktury a funkce pro záznam a výpis OSPFv3 topologie
- **main** - samotný program

#### Logické části programu

##### Odposlech zpráv na rozhranní

Pro odposlech byla použita knihovna libpcap, bez použití filtrace, což umožnilo zpracovat přijaté zprávy přímo v programu a vypsat tak přesné pořadové číslo tak, jak to dělá například program Wireshark. Pro použití filtru je však možné změnit definici FILTER\_EXP, v hlavičkovém souboru main.h. Stejně tak je možné zapnout/vypnout výpis ladících informací pomocí definice DEBUG, v hlavičkovém souboru const.h. Seznam dalšího nastavení překladu programu je obsažen v příloze 1.

##### Zpracování

O zpracování zprávy se stará funkce got\_packet, která postupně rozlišuje struktury zprávy dle jejího typu (IPv4/IPv6, OSPF typy zpráv), vypisuje celé tyto struktury na standartní výstup a ukládá relevantní informace do databáze za použití dříve uvedených modulů. Formát výpisu zprávy lze změnit pomocí změny definic ETHERNET\_FORMAT, IP\_FORMAT, OSPF\_HEADER\_FORMAT, OSPF\_TYPE\_FORMAT, OSPF\_LSA\_HEADER\_FORMAT a OSPF\_LSA\_FORMAT.

##### Tisk LSA

Je vhodné zmínit funkce pro tisk print\_ospf2\_lsa a print\_ospf3\_lsa. Tyto funkce přijímají jako parametr ukazatel na hlavičku LSA části OSPF zprávy, samostatně pak rozlišují typ předaného LSA a prostřednictvým pomocných funkcí tisknou LSA na standartní výstup. Problém nastává u struktur zprávy, které nemají přesně danou velikost jako například pole prefix u OSPFv3 Inter-Area-Prefix LSA, kde je nutné tuto velikost zjistit a pracovat s pamětí pouze v rozsahu zprávy. Dále se ve zprávách vyskytují pole, která se mohou opakovat. Je opět nutné ze zprávy zjistit počet opakování a tisknout pouze relevantní informace.

##### Databáze topologických informací

Databáze topologických informací je rozčleněna do několika struktur. Je vhodné rozlišovat informace od různých směrovačů, jejichž informace byla na rozhranní odposlechnuta a dále identifiční číslo instance procesu OSPF, která dané informace ze směrovače vyslala. LSA informace mohou patřit do různých oblastí a mohou být různého typu, což je potřeba pro efektivní prohledávání databáze také rozlišit. Vzhledem k tomu, že předem nevíme kolik routerů/instancí/oblastí budou odposlechnuté zprávy obsahovat, byly pro implementaci databáze zvoleny jednosměrně vázané seznamy. Na následujícím diagramu je znázorněna struktura databáze.

![Obr. 1 – Struktura Databáze](http://images.knapovsky.com/struktura-databaze.png)

Topologická databáze je po zaslání signálu SIGINT celá vytištěna na standartní výstup ve formátu blížícímu se výpisu topologické databáze na směrovačích Cisco.

## Použitá Literatura

- RFC5340, RFC2328
- Přednášky CCNA2

## Metriky projektu

3061 řádků kódu

## Příloha – Parametry překladu programu

Program je spustitelný na operačních systémech FreeBSD a Linux. Pro překlad na operačním systému FreeBSD použijte GNU Make bez parametrů.

\> gmake

Pro překlad na operačním systému Linux je potřeba dodat parametr linux.

 > make linux

V následující tabulce jsou uvedena různá nastavení programu, kterými lze změnit chování programu.

<table><colgroup><col> <col> </colgroup><tbody><tr><td><div class="layoutArea"><div class="column"><div></div>Nastavení<div></div></div></div></td><td><div class="layoutArea"><div class="column"><div></div>Popis<div></div></div></div></td></tr><tr><td><div class="layoutArea"><div class="column"><div></div>PRINT_IP<div></div></div></div></td><td><div class="layoutArea"><div class="column"><div></div>výpis IP hlaviček<div></div></div></div></td></tr><tr><td><div class="layoutArea"><div class="column"><div></div>PRINT_ETHERNET<div></div></div></div></td><td><div class="layoutArea"><div class="column"><div></div>výpis Ethernetových hlaviček<div></div></div></div></td></tr><tr><td><div class="layoutArea"><div class="column"><div></div>PRINT_PACKET_NUMBER<div></div></div></div></td><td><div class="layoutArea"><div class="column"><div></div>výpis pořadového čísla packetu<div></div></div></div></td></tr><tr><td><div class="layoutArea"><div class="column"><div></div>PRINT_OSPF_NUMBER<div></div></div></div></td><td><div class="layoutArea"><div class="column"><div></div>výpis pořadového čísla OSPF zprávy<div></div></div></div></td></tr><tr><td><div class="layoutArea"><div class="column"><div></div>IP_PRETTY_PRINT<div></div></div></div></td><td><div class="layoutArea"><div class="column"><div></div>zapne výpis zkraceného tvaru IP adres a prefixů<div></div></div></div></td></tr><tr><td><div class="layoutArea"><div class="column"><div></div>DEBUG<div></div></div></div></td><td><div class="layoutArea"><div class="column"><div></div>zapne výpis ladících zpráv<div></div></div></div></td></tr><tr><td><div class="layoutArea"><div class="column"><div></div>ETHERNET_FORMAT<div></div></div></div></td><td><div class="layoutArea"><div class="column"><div></div>odsazení výpisu Ethernetové hlavičky<div></div></div></div></td></tr><tr><td><div class="layoutArea"><div class="column"><div></div>IP_FORMAT<div></div></div></div></td><td><div class="layoutArea"><div class="column"><div></div>odsazení výpisu IP hlavičky<div></div></div></div></td></tr><tr><td><div class="layoutArea"><div class="column"><div></div>OSPF_HEADER_FORMAT<div></div></div></div></td><td><div class="layoutArea"><div class="column"><div></div>odsazení výpisu OSPF hlavičky<div></div></div></div></td></tr><tr><td><div class="layoutArea"><div class="column"><div></div>OSPF_TYPE_FORMAT<div></div></div></div></td><td><div class="layoutArea"><div class="column"><div></div>odsazení výpisu OSPF zprávy (Hello, DBU, ...)<div></div></div></div></td></tr><tr><td><div class="layoutArea"><div class="column"><div></div>OSPF_LSA_HEADER_FORMAT<div></div></div></div></td><td><div class="layoutArea"><div class="column"><div></div>odsazení výpisu LSA hlavičky<div></div></div></div></td></tr><tr><td><div class="layoutArea"><div class="column"><div></div>OSPF_LSA_FORMAT<div></div></div></div></td><td><div class="layoutArea"><div class="column"><div></div>odsazení výpisu LSA zprávy<div></div></div></div></td></tr><tr><td><div class="layoutArea"><div class="column"><div></div>PRINT_LLS<div></div></div></div></td><td><div class="layoutArea"><div class="column"><div></div>zapne výpis LLS bloku<div></div></div></div></td></tr></tbody></table>

Tato nastavení se provádějí změnou definic v hlavičkovém souboru const.h.

