#include <stdlib.h>
#include <stdio.h>
#include "net/ip/ports.h"

int main(int argc, const char** argv)
{
  if (argc == 2) {
    net::ip::ports ports;
    if (ports.build(argv[1])) {
      ports.print();

      return 0;
    } else {
      fprintf(stderr, "Error parsing port list.\n");
    }
  } else {
    fprintf(stderr, "Usage: %s <port-list>\n", argv[0]);
  }

  return -1;
}
