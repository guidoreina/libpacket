#ifndef NET_IP_TCP_MESSAGE_H
#define NET_IP_TCP_MESSAGE_H

#include <stdint.h>
#include <sys/mman.h>
#include "net/ip/endpoint.h"
#include "net/ip/tcp/direction.h"
#include "memory/file.h"

namespace net {
  namespace ip {
    namespace tcp {
      // TCP message.
      class message {
        public:
          // Default maximum buffer size.
          static constexpr const size_t
            default_max_buffer_size = 32 * 1024ul * 1024ul;

          // Constructor.
          message(const endpoint& client,
                  const endpoint& server,
                  direction dir);

          // Destructor.
          ~message();

          // Set maximum buffer size.
          void max_buffer_size(size_t size);

          // Clear.
          void clear();

          // Get path name.
          const char* pathname() const;

          // Set path name.
          bool pathname(const char* dir, const char* filename = nullptr);

          // Write to file at a given offset.
          bool pwrite(const void* buf, size_t count, size_t offset);

          // Finish message.
          bool finish(uint64_t timestamp);

          // Get data.
          const void* data() const;

          // Get length.
          size_t length() const;

        private:
          // Client.
          const endpoint& _M_client;

          // Server.
          const endpoint& _M_server;

          // Message direction.
          direction _M_direction;

          // Name of the file containing the message.
          char _M_filename[PATH_MAX] = {0};

          // Maximum buffer size.
          size_t _M_max_buffer_size = default_max_buffer_size;

          // File in memory.
          memory::file _M_mem_file;

          // File on disk.
          fs::file _M_disk_file;

          // File descriptor whose contents will be mapped into memory.
          int _M_fd = -1;

          // Pointer to the memory mapped area.
          void* _M_base = MAP_FAILED;

          // Length of the memory mapped area.
          size_t _M_length = 0;

          // Preferred location of the file.
          enum class location {
            memory,
            disk
          };

          location _M_location = location::memory;

          // Build pathname.
          bool build_pathname(const char* dir = ".");

          // Change "last modification time".
          bool change_last_modification_time(uint64_t timestamp);

          // Disable copy constructor and assignment operator.
          message(const message&) = delete;
          message& operator=(const message&) = delete;
      };

      inline message::message(const endpoint& client,
                              const endpoint& server,
                              direction dir)
        : _M_client(client),
          _M_server(server),
          _M_direction(dir)
      {
      }

      inline message::~message()
      {
        if (_M_base != MAP_FAILED) {
          munmap(_M_base, _M_length);
        }

        if (_M_fd != -1) {
          close(_M_fd);
        }
      }

      inline void message::max_buffer_size(size_t size)
      {
        _M_max_buffer_size = size;
      }

      inline const char* message::pathname() const
      {
        return _M_filename;
      }

      inline const void* message::data() const
      {
        return (_M_base == MAP_FAILED) ? _M_mem_file.data() : _M_base;
      }

      inline size_t message::length() const
      {
        return (_M_base == MAP_FAILED) ? _M_mem_file.length() : _M_length;
      }
    }
  }
}

#endif // NET_IP_TCP_MESSAGE_H
