CC=gcc
CFLAGS=-g
TARGET: test.exe CommandParser/libcli.a
LIBS=-lpthread -L ./CommandParser -lcli
OBJS=gluethread/glthread.o \
		graph.o			   \
		topologies.o	   \
		net.o			   \
		nwcli.o			   \
		utils.o			   \
		comm.o			   \
		layer2/layer2.o

test.exe:testapp.o ${OBJS} CommandParser/libcli.a
	${CC} ${CFLAGS} testapp.o ${OBJS} -o test.exe ${LIBS}

testapp.o:testapp.c
	${CC} ${CFLAGS} -c testapp.c -o testapp.o

gluethread/glthread.o:gluethread/glthread.c
	${CC} ${CFLAGS} -c -I gluethread gluethread/glthread.c -o gluethread/glthread.o

graph.o:graph.c
	${CC} ${CFLAGS} -c -I . graph.c -o graph.o

topologies.o:topologies.c
	${CC} ${CFLAGS} -c -I . topologies.c -o topologies.o

net.o: net.c
	${CC} ${CFLAGS} -c -I . net.c -o net.o

nwcli.o:nwcli.c
	${CC} ${CFLAGS} -c -I . nwcli.c  -o nwcli.o

CommandParser/libcli.a:
	(cd CommandParser; make)

comm.o:comm.c
	${CC} ${CFLAGS} -c -I . comm.c -o comm.o

Layer2/layer2.o:Layer2/layer2.c
	${CC} ${CFLAGS} -c -I . Layer2/layer2.c -o Layer2/layer2.o

clean:
	rm *.o
	rm gluethread/glthread.o
	rm layer2/layer2.o
	rm *.exe
	(cd CommandParser; make clean)

all:
	make
	(cd CommandParser; make)