#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>
#include <limits.h>
#include "pcap/ip/analyzer.h"
#include "net/ip/tcp/streams.h"

struct stream_data {
  char* filename;
  FILE* file;
};

static bool beginstreamfn(const net::ip::tcp::connection* conn,
                          net::ip::tcp::direction dir,
                          void*& user);

static void endstreamfn(const net::ip::tcp::connection* conn,
                        net::ip::tcp::direction dir,
                        void* user);

static bool payloadfn(const void* payload,
                      uint16_t payloadlen,
                      uint64_t offset,
                      const net::ip::tcp::connection* conn,
                      net::ip::tcp::direction dir,
                      void* user);

static bool gapfn(uint32_t gapsize,
                  uint64_t offset,
                  const net::ip::tcp::connection* conn,
                  net::ip::tcp::direction dir,
                  void* user);

static bool change_last_modification_time(const char* filename,
                                          uint64_t timestamp);

static const char* directory = nullptr;

int main(int argc, const char** argv)
{
  if (argc == 3) {
    struct stat sbuf;
    if ((stat(argv[2], &sbuf) == 0) && (S_ISDIR(sbuf.st_mode))) {
      // Open PCAP file.
      pcap::ip::analyzer analyzer;
      if (analyzer.open(argv[1])) {
        // Save directory.
        directory = argv[2];

        // Initialize streams.
        net::ip::tcp::streams streams;
        if (streams.init(beginstreamfn, endstreamfn, payloadfn, gapfn)) {
          pcap::ip::analyzer::const_iterator it;

          // Get first TCP segment.
          if (analyzer.begin(net::ip::protocol::tcp, it)) {
            do {
              // IPv4?
              if (it->version() == net::ip::version::v4) {
                streams.process(it->ipv4(),
                                it->tcp(),
                                it->l4(),
                                it->l4length(),
                                it->timestamp());
              } else {
                streams.process(it->ipv6(),
                                it->tcp(),
                                it->l4(),
                                it->l4length(),
                                it->timestamp());
              }
            } while (analyzer.next(net::ip::protocol::tcp, it));
          } else {
            printf("No connections.\n");
          }

          return 0;
        } else {
          fprintf(stderr, "Error initializing TCP streams.\n");
        }
      } else {
        fprintf(stderr, "Error opening PCAP file '%s'.\n", argv[1]);
      }
    } else {
      fprintf(stderr, "'%s' doesn't exist or is not a directory.\n", argv[2]);
    }
  } else {
    fprintf(stderr, "Usage: %s <filename> <directory>\n", argv[0]);
  }

  return -1;
}

bool beginstreamfn(const net::ip::tcp::connection* conn,
                   net::ip::tcp::direction dir,
                   void*& user)
{
  const uint64_t timestamp = (conn->creation_timestamp() != 0) ?
                               conn->creation_timestamp() :
                               conn->last_timestamp();

  const time_t t = timestamp / 1000000ull;
  struct tm tm;
  localtime_r(&t, &tm);

  const net::ip::endpoint&
    srcep = (dir == net::ip::tcp::direction::from_client) ? conn->client() :
                                                            conn->server();

  const net::ip::endpoint&
    dstep = (dir == net::ip::tcp::direction::from_client) ? conn->server() :
                                                            conn->client();

  const net::ip::address& from(srcep.address());
  const net::ip::address& to(dstep.address());

  char fromstr[INET6_ADDRSTRLEN];
  from.to_string(fromstr, sizeof(fromstr));

  char tostr[INET6_ADDRSTRLEN];
  to.to_string(tostr, sizeof(tostr));

  char filename[PATH_MAX];
  snprintf(filename,
           sizeof(filename),
           "%s/%04u%02u%02u-%02u%02u%02u.%06u--%s.%u--%s.%u",
           directory,
           1900 + tm.tm_year,
           1 + tm.tm_mon,
           tm.tm_mday,
           tm.tm_hour,
           tm.tm_min,
           tm.tm_sec,
           static_cast<unsigned>(timestamp % 1000000ull),
           fromstr,
           srcep.port(),
           tostr,
           dstep.port());

  FILE* file = fopen(filename, "w");

  if (file) {
    stream_data* data = static_cast<stream_data*>(malloc(sizeof(stream_data)));
    if (data) {
      if ((data->filename = strdup(filename)) != nullptr) {
        data->file = file;
        user = data;

        return true;
      }

      free(data);
    }

    fclose(file);
    unlink(filename);
  }

  return false;
}

void endstreamfn(const net::ip::tcp::connection* conn,
                 net::ip::tcp::direction dir,
                 void* user)
{
  if (user) {
    stream_data* data = static_cast<stream_data*>(user);

    fclose(data->file);

    struct stat sbuf;
    if (stat(data->filename, &sbuf) == 0) {
      // If the file is not empty...
      if (sbuf.st_size > 0) {
        change_last_modification_time(data->filename, conn->last_timestamp());
      } else {
        // Remove empty file.
        unlink(data->filename);
      }
    }

    free(data->filename);
    free(data);
  }
}

bool payloadfn(const void* payload,
               uint16_t payloadlen,
               uint64_t offset,
               const net::ip::tcp::connection* conn,
               net::ip::tcp::direction dir,
               void* user)
{
  if (user) {
    fwrite(payload, 1, payloadlen, static_cast<stream_data*>(user)->file);
  }

  return true;
}

bool gapfn(uint32_t gapsize,
           uint64_t offset,
           const net::ip::tcp::connection* conn,
           net::ip::tcp::direction dir,
           void* user)
{
  // Fill gap with zeroes.
  if (user) {
    static constexpr const uint8_t zeroes[4 * 1024] = {0};
    while (gapsize > 0) {
      const size_t to_write = (gapsize > sizeof(zeroes)) ? sizeof(zeroes) :
                                                           gapsize;

      fwrite(zeroes, 1, to_write, static_cast<stream_data*>(user)->file);
      gapsize -= to_write;
    }
  }

  return true;
}

bool change_last_modification_time(const char* filename, uint64_t timestamp)
{
  struct timespec times[2];
  times[0].tv_sec = timestamp / 1000000ull;
  times[1].tv_sec = times[0].tv_sec;

  times[0].tv_nsec = (timestamp % 1000000ull) * 1000ul;
  times[1].tv_nsec = times[0].tv_nsec;

  // Change file timestamps.
  return (utimensat(AT_FDCWD, filename, times, 0) == 0);
}
