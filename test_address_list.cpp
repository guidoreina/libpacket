#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "net/ip/address_list.h"

int main()
{
  net::ip::address_list addresses;

  uint32_t addr4;
  inet_pton(AF_INET, "127.0.0.1", &addr4);

  if (addresses.insert(addr4)) {
    inet_pton(AF_INET, "10.0.0.1", &addr4);

    if (addresses.insert(addr4)) {
      inet_pton(AF_INET, "127.0.0.1", &addr4);

      if (addresses.insert(addr4)) {
        struct in6_addr addr6;
        inet_pton(AF_INET6, "::1", &addr6);

        if ((addresses.insert(addr6)) && (addresses.insert(addr6))) {
          printf("List: '%s'.\n", addresses.to_string());

          return 0;
        }
      }
    }
  }

  fprintf(stderr, "Error inserting IP address.\n");

  return -1;
}
