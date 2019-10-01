#include <stdio.h>
#include <sys/stat.h>
#include "net/ip/tcp/message.h"

void net::ip::tcp::message::clear()
{
  *_M_filename = 0;

  _M_mem_file.clear();
  _M_disk_file.close();

  if (_M_base != MAP_FAILED) {
    munmap(_M_base, _M_length);
    _M_base = MAP_FAILED;
  }

  if (_M_fd != -1) {
    close(_M_fd);
    _M_fd = -1;
  }

  _M_length = 0;
}

bool net::ip::tcp::message::pathname(const char* dir, const char* filename)
{
  if (!filename) {
    if (build_pathname(dir)) {
      _M_location = location::disk;
      return true;
    }
  } else {
    if (snprintf(_M_filename, sizeof(_M_filename), "%s/%s", dir, filename) <
        static_cast<int>(sizeof(_M_filename))) {
      _M_location = location::disk;
      return true;
    }
  }

  return false;
}

bool net::ip::tcp::message::pwrite(const void* buf, size_t count, size_t offset)
{
  // If the file on disk has not been opened...
  if (!_M_disk_file.open()) {
    // If the file in memory won't become too big after the change...
    if (offset + count <= _M_max_buffer_size) {
      return _M_mem_file.pwrite(buf, count, offset);
    } else {
      // If the filename has not been set...
      if (!*_M_filename) {
        build_pathname();
      }

      return ((_M_disk_file.open(_M_filename)) &&
              (_M_disk_file.write(_M_mem_file.data(), _M_mem_file.length())) &&
              (_M_disk_file.pwrite(buf, count, offset)));
    }
  } else {
    return _M_disk_file.pwrite(buf, count, offset);
  }
}

bool net::ip::tcp::message::finish(uint64_t timestamp)
{
  if (_M_location == location::memory) {
    // If the file on disk has not been opened...
    if (!_M_disk_file.open()) {
      return true;
    } else {
      // Get file size.
      _M_length = _M_disk_file.tell();

      // Close file on disk.
      _M_disk_file.close();

      // Change file timestamps.
      change_last_modification_time(timestamp);

      // Open file for reading.
      if ((_M_fd = open(_M_filename, O_RDONLY)) != -1) {
        // Map file into memory.
        if ((_M_base = mmap(nullptr,
                            _M_length,
                            PROT_READ,
                            MAP_SHARED,
                            _M_fd,
                            0)) != MAP_FAILED) {
          return true;
        }
      }
    }

    return false;
  } else {
    // If the file on disk has not been opened yet...
    if (!_M_disk_file.open()) {
      if ((!_M_disk_file.open(_M_filename)) ||
          (!_M_disk_file.write(_M_mem_file.data(), _M_mem_file.length()))) {
        return false;
      }
    }

    // Get file size.
    _M_length = _M_disk_file.tell();

    // Close file on disk.
    _M_disk_file.close();

    // Change file timestamps.
    change_last_modification_time(timestamp);

    return true;
  }
}

bool net::ip::tcp::message::build_pathname(const char* dir)
{
  char client[INET6_ADDRSTRLEN];
  char server[INET6_ADDRSTRLEN];
  if ((_M_client.address().to_string(client, sizeof(client))) &&
      (_M_server.address().to_string(server, sizeof(server)))) {
    if (_M_direction == direction::from_client) {
      return (snprintf(_M_filename,
                       sizeof(_M_filename),
                       "%s/%s.%u-%s.%u",
                       dir,
                       client,
                       _M_client.port(),
                       server,
                       _M_server.port()) <
              static_cast<int>(sizeof(_M_filename)));
    } else {
      return (snprintf(_M_filename,
                       sizeof(_M_filename),
                       "%s/%s.%u-%s.%u",
                       dir,
                       server,
                       _M_server.port(),
                       client,
                       _M_client.port()) <
              static_cast<int>(sizeof(_M_filename)));
    }
  } else {
    return false;
  }
}

bool net::ip::tcp::message::change_last_modification_time(uint64_t timestamp)
{
  struct timespec times[2];
  times[0].tv_sec = timestamp / 1000000ull;
  times[1].tv_sec = times[0].tv_sec;

  times[0].tv_nsec = (timestamp % 1000000ull) * 1000;
  times[1].tv_nsec = times[0].tv_nsec;

  // Change file timestamps.
  return (utimensat(AT_FDCWD, _M_filename, times, 0) == 0);
}
