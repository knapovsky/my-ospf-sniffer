# Projekt do predmetu ISA - OSPFv2, OSPFv3 sniffer s vypsanim databaze
# soubor: 	Makefile
#
# Autor:	Martin Knapovsky
# E-Mail:	xknapo02@stud.vutbr.cz
# Datum:	5.11.2011
#
# Popis souboru: Soubor pro preklad projektu.
# Pouziti:  make - samotny preklad
#           make clean - odstraneni docasnych souboru
#           make pack - vytvoreni archivu se zdrojovymi kody
#           make line - vypocet radku programu
#           make optimalize - optimalizovany preklad
#

CFLAGS=-Wall 
CFLAGS2=-Wall -O2
DBG=-DDEBUG
BIN=myospfsniffer
CC=gcc
FILES=manual.pdf Readme main.h main.c const.h sys.h sys.c binary.c ospfv2.h ospfv2.c ospfv3.h ospfv3.c ospfv3_db.h ospfv3_db.c Makefile

ALL:	sys.o const.h binary.o ospfv2.o ospfv3.o ospfv3_db.o main.o
	$(CC) $(CFLAGS) -o $(BIN) -D_BSD_SOURCE -lpcap sys.o binary.o ospfv2.o ospfv3.o ospfv3_db.o main.o

optimalize:	sys.o const.h binary.o ospfv2.o ospfv3.o ospfv3_db.o main.o
	$(CC) $(CFLAGS2) -o $(BIN) -D_BSD_SOURCE -lpcap sys.o binary.o ospfv2.o ospfv3.o ospfv3_db.o main.o

sys.o: sys.h sys.c
	$(CC) $(CFLAGS) -D_BSD_SOURCE -c sys.c -o sys.o

const.o: const.h
	$(CC) $(CFLAGS) -D_BSD_SOURCE -c const.h -o const.o

binary.o: binary.c
	$(CC) $(CFLAGS) -D_BSD_SOURCE -c binary.c -o binary.o

ospfv2.o: ospfv2.h ospfv2.c
	$(CC) $(CFLAGS) -D_BSD_SOURCE -c ospfv2.c -o ospfv2.o

ospfv3.o: ospfv3.h ospfv3.c
	$(CC) $(CFLAGS) -D_BSD_SOURCE -c ospfv3.c -o ospfv3.o

ospfv3_db.o: ospfv3_db.h ospfv3_db.c
	$(CC) $(CFLAGS) -D_BSD_SOURCE -c ospfv3_db.c -o ospfv3_db.o

main.o: main.h main.c
	$(CC) $(CFLAGS)  -D_BSD_SOURCE -c main.c -o main.o

linux:	sys_l.o const.h binary_l.o ospfv2_l.o ospfv3_l.o ospfv3_db_l.o main_l.o
	$(CC) $(CFLAGS) -o $(BIN) -lpcap sys_l.o binary_l.o ospfv2_l.o ospfv3_l.o ospfv3_db_l.o main_l.o

optimalize_linux:	ys_l.o const.h binary_l.o ospfv2_l.o ospfv3_l.o ospfv3_db_l.o main_l.o
	$(CC) $(CFLAGS2) -o $(BIN) -lpcap sys_l.o binary_l.o ospfv2_l.o ospfv3_l.o ospfv3_db_l.o main_l.o

sys_l.o: sys.h sys.c
	$(CC) $(CFLAGS) -D_LINUX_SOURCE -c sys.c -o sys_l.o

const_l.o: const.h
	$(CC) $(CFLAGS) -c const.h -o const_l.o

binary_l.o: binary.c
	$(CC) $(CFLAGS) -c binary.c -o binary_l.o

ospfv2_l.o: ospfv2.h ospfv2.c
	$(CC) $(CFLAGS) -c ospfv2.c -o ospfv2_l.o

ospfv3_l.o: ospfv3.h ospfv3.c
	$(CC) $(CFLAGS) -c ospfv3.c -o ospfv3_l.o

ospfv3_db_l.o: ospfv3_db.h ospfv3_db.c
	$(CC) $(CFLAGS) -c ospfv3_db.c -o ospfv3_db_l.o

main_l.o: main.h main.c
	$(CC) $(CFLAGS) -c main.c -o main_l.o

clean:
	rm -f $(BIN) *.o *~ tt_*

pack:
	tar cf xknapo02.tar $(FILES)

lines:
	wc -l $(FILES)
