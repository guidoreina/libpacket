#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <inttypes.h>
#include "net/ip/statistics.h"
#include "pcap/ip/analyzer.h"

static bool parse_arguments(int argc,
                            const char** argv,
                            const char*& svcdirname,
                            const char*& pcapfilename,
                            const char*& csvdirname,
                            const char*& pcapdirname);

static void usage(const char* program);

int main(int argc, const char** argv)
{
  // Parse arguments.
  const char* svcdirname;
  const char* pcapfilename;
  const char* csvdirname;
  const char* pcapdirname;
  if (parse_arguments(argc,
                      argv,
                      svcdirname,
                      pcapfilename,
                      csvdirname,
                      pcapdirname)) {
    // Load services.
    net::ip::statistics statistics;
    if (statistics.load(svcdirname)) {
      // If a directory for the CSV files has been specified...
      if (csvdirname) {
        if (!statistics.generate_csv_files(csvdirname)) {
          fprintf(stderr, "Invalid directory '%s'.\n", csvdirname);
          return -1;
        }
      }

      // If a directory for the PCAP files has been specified...
      if (pcapdirname) {
        if (!statistics.generate_pcap_files(pcapdirname)) {
          fprintf(stderr, "Invalid directory '%s'.\n", pcapdirname);
          return -1;
        }
      }

      // Open PCAP file.
      pcap::ip::analyzer analyzer;
      if (analyzer.open(pcapfilename)) {
        pcap::ip::analyzer::const_iterator it;
        if (analyzer.begin(it)) {
          uint64_t npkt = 0;

          do {
            npkt++;

            // IPv4?
            if (it->version() == net::ip::version::v4) {
              // TCP?
              if (it->is_tcp()) {
                if (!statistics.process(it->ipv4(),
                                        it->tcp(),
                                        it->length(),
                                        it->l4length(),
                                        it->timestamp())) {
                  fprintf(stderr,
                          "Error processing packet %" PRIu64 ".\n",
                          npkt);

                  return false;
                }
              } else if (it->is_udp()) {
                if (!statistics.process(it->ipv4(),
                                        it->udp(),
                                        it->length(),
                                        it->l4length(),
                                        it->timestamp())) {
                  fprintf(stderr,
                          "Error processing packet %" PRIu64 ".\n",
                          npkt);

                  return false;
                }
              }
            } else {
              // TCP?
              if (it->is_tcp()) {
                if (!statistics.process(it->ipv6(),
                                        it->tcp(),
                                        it->length(),
                                        it->l4length(),
                                        it->timestamp())) {
                  fprintf(stderr,
                          "Error processing packet %" PRIu64 ".\n",
                          npkt);

                  return false;
                }
              } else if (it->is_udp()) {
                if (!statistics.process(it->ipv6(),
                                        it->udp(),
                                        it->length(),
                                        it->l4length(),
                                        it->timestamp())) {
                  fprintf(stderr,
                          "Error processing packet %" PRIu64 ".\n",
                          npkt);

                  return false;
                }
              }
            }
          } while (analyzer.next(it));
        }

        // Print statistics.
        statistics.print();

        return 0;
      } else {
        fprintf(stderr, "Error opening PCAP file '%s'.\n", pcapfilename);
      }
    }
  }

  return -1;
}

bool parse_arguments(int argc,
                     const char** argv,
                     const char*& svcdirname,
                     const char*& pcapfilename,
                     const char*& csvdirname,
                     const char*& pcapdirname)
{
  // Set default values.
  svcdirname = nullptr;
  pcapfilename = nullptr;
  csvdirname = nullptr;
  pcapdirname = nullptr;

  int i = 1;
  while (i < argc) {
    if (strcasecmp(argv[i], "--services-directory") == 0) {
      // If not the last argument...
      if (i + 1 < argc) {
        struct stat sbuf;
        if ((stat(argv[i + 1], &sbuf) == 0) && (S_ISDIR(sbuf.st_mode))) {
          svcdirname = argv[i + 1];

          i += 2;
        } else {
          fprintf(stderr,
                  "'%s' doesn't exist or is not a directory.\n",
                  argv[i + 1]);

          return false;
        }
      } else {
        fprintf(stderr, "Expected directory after \"--services-directory\".\n");
        return false;
      }
    } else if (strcasecmp(argv[i], "--pcap") == 0) {
      // If not the last argument...
      if (i + 1 < argc) {
        struct stat sbuf;
        if ((stat(argv[i + 1], &sbuf) == 0) && (S_ISREG(sbuf.st_mode))) {
          pcapfilename = argv[i + 1];

          i += 2;
        } else {
          fprintf(stderr,
                  "'%s' doesn't exist or is not a file.\n",
                  argv[i + 1]);

          return false;
        }
      } else {
        fprintf(stderr, "Expected filename after \"--pcap\".\n");
        return false;
      }
    } else if (strcasecmp(argv[i], "--csv-directory") == 0) {
      // If not the last argument...
      if (i + 1 < argc) {
        struct stat sbuf;
        if ((stat(argv[i + 1], &sbuf) == 0) && (S_ISDIR(sbuf.st_mode))) {
          csvdirname = argv[i + 1];

          i += 2;
        } else {
          fprintf(stderr,
                  "'%s' doesn't exist or is not a directory.\n",
                  argv[i + 1]);

          return false;
        }
      } else {
        fprintf(stderr, "Expected directory after \"--csv-directory\".\n");
        return false;
      }
    } else if (strcasecmp(argv[i], "--pcap-directory") == 0) {
      // If not the last argument...
      if (i + 1 < argc) {
        struct stat sbuf;
        if ((stat(argv[i + 1], &sbuf) == 0) && (S_ISDIR(sbuf.st_mode))) {
          pcapdirname = argv[i + 1];

          i += 2;
        } else {
          fprintf(stderr,
                  "'%s' doesn't exist or is not a directory.\n",
                  argv[i + 1]);

          return false;
        }
      } else {
        fprintf(stderr, "Expected directory after \"--pcap-directory\".\n");
        return false;
      }
    } else {
      usage(argv[0]);
      return false;
    }
  }

  if (svcdirname) {
    if (pcapfilename) {
      return true;
    } else {
      fprintf(stderr, "Parameter \"--pcap\" is mandatory.\n");
      return false;
    }
  } else if (pcapfilename) {
    fprintf(stderr, "Parameter \"--services-directory\" is mandatory.\n");
    return false;
  }

  if (argc == 1) {
    usage(argv[0]);
  } else {
    fprintf(stderr,
            "Parameters \"--services-directory\" and \"--pcap\" are "
            "mandatory.\n");
  }

  return false;
}

void usage(const char* program)
{
  fprintf(stderr,
          "Usage: %s --services-directory <directory> --pcap <filename> "
          "[--csv-directory <directory>] [--pcap-directory <directory>]\n",
          program);
}
