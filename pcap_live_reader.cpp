#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include <signal.h>
#include <inttypes.h>
#include "pcap/live_reader.h"

static void signal_handler(int nsig);
static const char* timestamp_to_string(uint64_t timestamp, char* s, size_t len);
static const char* timestamp_to_string(time_t sec,
                                       suseconds_t usec,
                                       char* s,
                                       size_t len);

static bool running = false;

int main(int argc, const char** argv)
{
  if (argc == 2) {
    // Open PCAP file.
    pcap::live_reader reader;
    if (reader.open(argv[1])) {
      // Install signal handler.
      struct sigaction act;
      sigemptyset(&act.sa_mask);
      act.sa_flags = 0;
      act.sa_handler = signal_handler;
      sigaction(SIGTERM, &act, nullptr);
      sigaction(SIGINT, &act, nullptr);

      running = true;

      pcap::packet pkt;

      uint64_t npackets = 0;

      do {
        // Read next packet.
        while (reader.read(pkt)) {
          // Get current time.
          struct timeval tv;
          gettimeofday(&tv, nullptr);

          char timestr[64];
          char pkttimestr[64];
          printf("Current time: %s, packet time: %s, packet length: %u.\n",
                 timestamp_to_string(tv.tv_sec,
                                     tv.tv_usec,
                                     timestr,
                                     sizeof(timestr)),
                 timestamp_to_string(pkt.timestamp(),
                                     pkttimestr,
                                     sizeof(pkttimestr)),
                 pkt.length());

          npackets++;
        }

        // End of file?
        if (reader.feof()) {
          printf("==================== End of file ====================\n");

          // Sleep interval.
          static constexpr const useconds_t sleep_interval = 500 * 1000;

          usleep(sleep_interval);
        } else {
          fprintf(stderr, "Error reading from file.\n");
          break;
        }
      } while (running);

      printf("# packets: %" PRIu64 ".\n", npackets);

      return 0;
    } else {
      fprintf(stderr, "Error opening PCAP file '%s'.\n", argv[1]);
    }
  } else {
    fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
  }

  return -1;
}

void signal_handler(int nsig)
{
  printf("Received signal %d.\n", nsig);

  running = false;
}

const char* timestamp_to_string(uint64_t timestamp, char* s, size_t len)
{
  return timestamp_to_string(timestamp / 1000000ull,
                             timestamp % 1000000ull,
                             s,
                             len);
}

const char* timestamp_to_string(time_t sec,
                                suseconds_t usec,
                                char* s,
                                size_t len)
{
  struct tm tm;
  localtime_r(&sec, &tm);

  snprintf(s,
           len,
           "%04u/%02u/%02u %02u:%02u:%02u.%06u",
           1900 + tm.tm_year,
           1 + tm.tm_mon,
           tm.tm_mday,
           tm.tm_hour,
           tm.tm_min,
           tm.tm_sec,
           static_cast<unsigned>(usec));

  return s;
}
