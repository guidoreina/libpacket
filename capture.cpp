#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include "net/ip/parser.h"
#include "net/ip/address.h"
#include "net/capture/ring_buffer.h"

static void ethernetfn(const void* buf,
                       uint32_t len,
                       const struct timeval& timestamp,
                       void* user);

static void signal_handler(int nsig);

static bool running = false;

int main(int argc, const char** argv)
{
  if (argc == 2) {
    // IP parser.
    net::ip::parser parser;

    // Create capture device.
    net::capture::ring_buffer capture(ethernetfn, &parser);
    if (capture.create(argv[1])) {
      // Install signal handler.
      struct sigaction act;
      sigemptyset(&act.sa_mask);
      act.sa_flags = 0;
      act.sa_handler = signal_handler;
      sigaction(SIGTERM, &act, nullptr);
      sigaction(SIGINT, &act, nullptr);

      running = true;

      do {
        capture.read();
      } while (running);

      // Show statistics.
      capture.show_statistics();

      return 0;
    } else {
      fprintf(stderr,
              "Error creating capture device for interface '%s'.\n",
              argv[1]);
    }
  } else {
    fprintf(stderr, "Usage: %s <interface-name>\n", argv[0]);
  }

  return -1;
}

void ethernetfn(const void* buf,
                uint32_t len,
                const struct timeval& timestamp,
                void* user)
{
  net::ip::parser* parser = static_cast<net::ip::parser*>(user);

  // Process ethernet frame.
  net::ip::packet pkt;
  if (parser->process_ethernet(buf,
                               len,
                               (timestamp.tv_sec * 1000000ull) +
                               static_cast<uint64_t>(timestamp.tv_usec),
                               &pkt)) {
    char from[INET6_ADDRSTRLEN];
    char to[INET6_ADDRSTRLEN];

    if (pkt.version() == net::ip::version::v4) {
      net::ip::address saddr(pkt.ipv4()->saddr);
      saddr.to_string(from, sizeof(from));

      net::ip::address daddr(pkt.ipv4()->daddr);
      daddr.to_string(to, sizeof(to));
    } else {
      net::ip::address saddr(pkt.ipv6()->ip6_src);
      saddr.to_string(from, sizeof(from));

      net::ip::address daddr(pkt.ipv6()->ip6_dst);
      daddr.to_string(to, sizeof(to));
    }

    if (pkt.is_tcp()) {
      printf("[TCP] %s:%u -> %s:%u, payload length: %u.\n",
             from,
             ntohs(pkt.tcp()->source),
             to,
             ntohs(pkt.tcp()->dest),
             pkt.l4length());
    } else if (pkt.is_udp()) {
      printf("[UDP] %s:%u -> %s:%u, payload length: %u.\n",
             from,
             ntohs(pkt.udp()->source),
             to,
             ntohs(pkt.udp()->dest),
             pkt.l4length());
    } else if (pkt.is_icmp()) {
      printf("[ICMP] %s -> %s, payload length: %u.\n",
             from,
             to,
             pkt.l4length());
    } else {
      printf("%s -> %s, length: %u.\n", from, to, len);
    }
  }
}

void signal_handler(int nsig)
{
  printf("Received signal %d.\n", nsig);

  running = false;
}
