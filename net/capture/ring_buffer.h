#ifndef NET_CAPTURE_RING_BUFFER_H
#define NET_CAPTURE_RING_BUFFER_H

#include <sys/mman.h>
#include <sys/uio.h>
#include <poll.h>
#include <net/if.h>
#include <limits.h>
#include <linux/if_packet.h>
#include <linux/filter.h>
#include "net/capture/callback.h"

namespace net {
  namespace capture {
    // Ring buffer.
    class ring_buffer {
      public:
        // Minimum block size (4 KiB).
        static constexpr const size_t
               min_block_size = static_cast<size_t>(1) << 12;

        // Maximum block size.
        static constexpr const size_t max_block_size = ULONG_MAX;

        // Default block size (4 MiB).
        static constexpr const size_t
               default_block_size = static_cast<size_t>(1) << 22;

        // Minimum frame size.
        static constexpr const size_t min_frame_size = 128;

        // Maximum frame size.
        static constexpr const size_t max_frame_size = ULONG_MAX;

        // Default frame size (2 KiB).
        static constexpr const size_t
               default_frame_size = static_cast<size_t>(1) << 11;

        // Minimum number of frames.
        static constexpr const size_t min_frames = 8;

        // Maximum number of frames.
        static constexpr const size_t max_frames = ULONG_MAX;

        // Default number of frames (131072).
        static constexpr const size_t
               default_frames = static_cast<size_t>(1) << 17;

        // Default read timeout (in milliseconds).
        static constexpr const int default_read_timeout = 100;

        // Constructor.
        ring_buffer(ethernetfn_t ethernetfn, void* user);

        // Destructor.
        ~ring_buffer();

        // Clear.
        void clear();

        // Create.
        bool create(const char* interface,
                    int rcvbuf_size = 0,
                    bool promiscuous_mode = true,
                    size_t block_size = default_block_size,
                    size_t frame_size = default_frame_size,
                    size_t frame_count = default_frames,
                    const struct sock_fprog* fprog = nullptr);

        bool create(unsigned ifindex,
                    int rcvbuf_size = 0,
                    bool promiscuous_mode = true,
                    size_t block_size = default_block_size,
                    size_t frame_size = default_frame_size,
                    size_t frame_count = default_frames,
                    const struct sock_fprog* fprog = nullptr);

        // Read next packet(s).
        // Returns:
        //   -1: Error.
        //    0: Timeout.
        //    1: Packet was read.
        int read(int timeout = default_read_timeout);

        // Show statistics.
        bool show_statistics();

      private:
        // Socket.
        int _M_fd = -1;

        // Buffer for the ring buffer.
        void* _M_buf = MAP_FAILED;
        size_t _M_ring_size;

        // For TPACKET_V2:
        //   _M_count = req.tp_frame_nr
        //   _M_size = req.tp_frame_size
        //
        // For TPACKET_V3:
        //   _M_count = req3.tp_block_nr
        //   _M_size = req3.tp_block_size
        size_t _M_count;
        size_t _M_size;

        // Frames.
        struct iovec* _M_frames = nullptr;

        // Number of frames.
        size_t _M_nframes;

        // Index of the next packet.
        size_t _M_idx = 0;

        // Poll file descriptor.
        struct pollfd _M_pollfd;

        // Ethernet frame callback.
        ethernetfn_t _M_ethernetfn;
        void* _M_user;

        // Set up socket.
        bool setup_socket(int rcvbuf_size,
                          bool promiscuous_mode,
                          unsigned ifindex,
                          const struct sock_fprog* fprog);

        // Set up packet ring.
        bool setup_ring(size_t block_size,
                        size_t frame_size,
                        size_t frame_count);

        // Set up mmap packet ring.
        bool mmap_ring();

        // Bind packet ring.
        bool bind_ring(unsigned ifindex);

#if HAVE_TPACKET_V3
        // Configure for TPACKET_V3.
        void config_v3(size_t block_size,
                       size_t frame_size,
                       size_t frame_count,
                       struct tpacket_req3& req);

        // Receive packet for TPACKET_V3.
        bool recv_v3();
#else
        // Configure for TPACKET_V2.
        void config_v2(size_t block_size,
                       size_t frame_size,
                       size_t frame_count,
                       struct tpacket_req& req);

        // Receive packet for TPACKET_V2.
        bool recv_v2();
#endif

        // Disable copy constructor and assignment operator.
        ring_buffer(const ring_buffer&) = delete;
        ring_buffer& operator=(const ring_buffer&) = delete;
    };

    inline ring_buffer::ring_buffer(ethernetfn_t ethernetfn, void* user)
      : _M_ethernetfn(ethernetfn),
        _M_user(user)
    {
    }

    inline ring_buffer::~ring_buffer()
    {
      clear();
    }

    inline bool ring_buffer::create(const char* interface,
                                    int rcvbuf_size,
                                    bool promiscuous_mode,
                                    size_t block_size,
                                    size_t frame_size,
                                    size_t frame_count,
                                    const struct sock_fprog* fprog)
    {
      return create(if_nametoindex(interface),
                    rcvbuf_size,
                    promiscuous_mode,
                    block_size,
                    frame_size,
                    frame_count,
                    fprog);
    }
  }
}

#endif // NET_CAPTURE_RING_BUFFER_H
