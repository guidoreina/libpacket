#include <stdlib.h>
#include <stdio.h>
#include "net/ip/services.h"

int main(int argc, const char** argv)
{
  if (argc == 3) {
    struct in_addr addr;
    if (inet_pton(AF_INET, argv[2], &addr) == 1) {
      // Load services.
      net::ip::services services;
      if (services.load(argv[1])) {
        net::ip::service::identifier id;
        if (services.find(addr, id)) {
          printf("%s", services.name(id));
        }

        return 0;
      }
    } else {
      struct in6_addr addr;
      if (inet_pton(AF_INET6, argv[2], &addr) == 1) {
        // Load services.
        net::ip::services services;
        if (services.load(argv[1])) {
          net::ip::service::identifier id;
          if (services.find(addr, id)) {
            printf("%s", services.name(id));
          }

          return 0;
        }
      } else {
        fprintf(stderr, "Invalid IP address '%s'.\n", argv[2]);
      }
    }
  } else {
    fprintf(stderr, "Usage: %s <directory> <ip-address>\n", argv[0]);
  }

  return -1;
}
