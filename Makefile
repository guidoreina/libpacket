CC=g++
CXXFLAGS=-O3 -std=c++11 -Wall -pedantic -D_GNU_SOURCE -I. -fPIC
CXXFLAGS+=-DHAVE_TPACKET_V3

LDFLAGS=-shared

MAKEDEPEND=${CC} -MM
LIBRARY=libpacket.so

OBJS = util/hash.o string/buffer.o memory/file.o fs/file.o pcap/reader.o \
       pcap/ip/analyzer.o pcap/ip/tcp/connection/analyzer.o \
       net/ip/fragmented_packet.o net/ip/fragmented_packets.o net/ip/parser.o \
       net/ip/packets.o net/ip/endpoint.o net/ip/tcp/connection.o \
       net/ip/tcp/connections.o net/ip/tcp/segment.o net/ip/tcp/segments.o \
       net/ip/tcp/stream.o net/ip/tcp/streams.o net/ip/tcp/message.o \
       net/ip/dns/message.o net/ip/ports.o net/capture/ring_buffer.o \
       net/ip/services.o

DEPS:= ${OBJS:%.o=%.d}

all: $(LIBRARY)

${LIBRARY}: ${OBJS}
	${CC} ${OBJS} ${LIBS} -o $@ ${LDFLAGS}

clean:
	rm -f ${LIBRARY} ${OBJS} ${DEPS}

${OBJS} ${DEPS} ${LIBRARY} : Makefile

.PHONY : all clean

%.d : %.cpp
	${MAKEDEPEND} ${CXXFLAGS} $< -MT ${@:%.d=%.o} > $@

%.o : %.cpp
	${CC} ${CXXFLAGS} -c -o $@ $<

-include ${DEPS}
