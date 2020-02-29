#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include "pcap/reader.h"

bool pcap::reader::open(const char* filename)
{
  // Open standard input?
  if ((!filename) || (!*filename) || (strcmp(filename, "-") == 0)) {
    if (_M_stream.open(STDIN_FILENO)) {
      _M_close = &reader::stream_close;
      _M_filesize = &reader::stream_filesize;
      _M_file_header = &reader::stream_file_header;
      _M_linktype = &reader::stream_linktype;
      _M_begin = &reader::stream_begin;
      _M_next = &reader::stream_next;

      return true;
    }
  } else {
    if (_M_file.open(filename)) {
      _M_close = &reader::file_close;
      _M_filesize = &reader::file_filesize;
      _M_file_header = &reader::file_file_header;
      _M_linktype = &reader::file_linktype;
      _M_begin = &reader::file_begin;
      _M_next = &reader::file_next;

      return true;
    }
  }

  return false;
}

bool pcap::reader::file::open(const char* filename)
{
  // If the file exists and is big enough to contain the PCAP file header...
  struct stat sbuf;
  if ((stat(filename, &sbuf) == 0) &&
      (S_ISREG(sbuf.st_mode)) &&
      (sbuf.st_size >= static_cast<off_t>(sizeof(pcap::file_header)))) {
    // Open file for reading.
    if ((_M_fd = ::open(filename, O_RDONLY)) != -1) {
      // Map file into memory.
      if ((_M_base = mmap(nullptr,
                          sbuf.st_size,
                          PROT_READ,
                          MAP_SHARED,
                          _M_fd,
                          0)) != MAP_FAILED) {
        // Save file size.
        _M_filesize = sbuf.st_size;

        // Check magic.
        switch (static_cast<magic>(file_header()->magic)) {
          case magic::microseconds:
            _M_resolution = resolution::microseconds;
            break;
          case magic::nanoseconds:
            _M_resolution = resolution::nanoseconds;
            break;
          default:
            return false;
        }

        // Version 2.4?
        if ((file_header()->version_major == version_major) &&
            (file_header()->version_minor == version_minor)) {
          // Make '_M_begin' point to the first packet.
          _M_begin = static_cast<const uint8_t*>(_M_base) +
                     sizeof(pcap::file_header);

          // Make '_M_end' point to the end.
          _M_end = static_cast<const uint8_t*>(_M_base) + _M_filesize;

          return true;
        }
      }
    }
  }

  return false;
}

void pcap::reader::file::close()
{
  if (_M_base != MAP_FAILED) {
    munmap(_M_base, _M_filesize);
    _M_base = MAP_FAILED;
  }

  if (_M_fd != -1) {
    ::close(_M_fd);
    _M_fd = -1;
  }
}

bool pcap::reader::file::next(packet& pkt)
{
  // Make 'data' point to the packet data.
  const uint8_t* const data = pkt._M_next + sizeof(pkthdr);

  // If the packet data is not beyond the end of the file...
  if (data <= _M_end) {
    const pkthdr* const hdr = reinterpret_cast<const pkthdr*>(pkt._M_next);

    // Make 'next' point to the next packet.
    const uint8_t* const next = data + hdr->caplen;

    // If the next packet is not beyond the end of the file...
    if (next <= _M_end) {
      pkt._M_data = data;
      pkt._M_length = hdr->caplen;

      if (_M_resolution == resolution::microseconds) {
        pkt._M_timestamp = (hdr->ts.tv_sec * 1000000ull) + hdr->ts.tv_usec;
      } else {
        pkt._M_timestamp = (hdr->ts.tv_sec * 1000000ull) +
                           (hdr->ts.tv_usec / 1000);
      }

      pkt._M_next = next;

      return true;
    }
  }

  return false;
}

bool pcap::reader::stream::open(int fd)
{
  uint8_t* buf = reinterpret_cast<uint8_t*>(&_M_file_header);
  size_t left = sizeof(pcap::file_header);

  // Read PCAP file header.
  do {
    const ssize_t ret = ::read(fd, buf, left);
    if (ret > 0) {
      if ((left -= ret) == 0) {
        break;
      } else {
        buf += ret;
      }
    } else if ((ret == 0) || (errno != EINTR)) {
      return false;
    }
  } while (true);

  // Check magic.
  switch (static_cast<magic>(_M_file_header.magic)) {
    case magic::microseconds:
      _M_resolution = resolution::microseconds;
      break;
    case magic::nanoseconds:
      _M_resolution = resolution::nanoseconds;
      break;
    default:
      return false;
  }

  // Version 2.4?
  if ((_M_file_header.version_major == version_major) &&
      (_M_file_header.version_minor == version_minor)) {
    // Create buffer.
    if ((_M_buf = static_cast<uint8_t*>(malloc(buffer_size))) != nullptr) {
      _M_bufend = _M_buf + buffer_size;
      _M_dataend = _M_buf;

      _M_fd = fd;

      return true;
    }
  }

  return false;
}

bool pcap::reader::stream::next(packet& pkt)
{
  // Read PCAP packet header (if not already contained in the buffer).
  do {
    // If the PCAP packet header is already contained in the buffer...
    if (_M_pkt + sizeof(pkthdr) <= _M_dataend) {
      break;
    } else {
      // Read from the stream.
      if (!read()) {
        return false;
      }
    }
  } while (true);

  const size_t
    len = sizeof(pkthdr) + reinterpret_cast<const pkthdr*>(_M_pkt)->caplen;

  // If the packet is not too big...
  if (len <= buffer_size) {
    do {
      const size_t count = _M_dataend - _M_pkt;
      if (count >= len) {
        const pkthdr* const hdr = reinterpret_cast<const pkthdr*>(_M_pkt);

        pkt._M_data = _M_pkt + sizeof(pkthdr);
        pkt._M_length = hdr->caplen;

        if (_M_resolution == resolution::microseconds) {
          pkt._M_timestamp = (hdr->ts.tv_sec * 1000000ull) + hdr->ts.tv_usec;
        } else {
          pkt._M_timestamp = (hdr->ts.tv_sec * 1000000ull) +
                             (hdr->ts.tv_usec / 1000);
        }

        // Make '_M_pkt' point to the next packet.
        _M_pkt += len;

        return true;
      } else {
        // Read from the stream.
        if (!read()) {
          return false;
        }
      }
    } while (true);
  }

  return false;
}

bool pcap::reader::stream::read()
{
  if (_M_pkt != _M_buf) {
    const size_t len = _M_dataend - _M_pkt;

    if (len > 0) {
      memmove(_M_buf, _M_pkt, len);
      _M_dataend = _M_buf + len;
    } else {
      _M_dataend = _M_buf;
    }

    _M_pkt = _M_buf;
  }

  do {
    const ssize_t ret = ::read(_M_fd, _M_dataend, _M_bufend - _M_dataend);
    if (ret > 0) {
      _M_dataend += ret;
      return true;
    } else if ((ret == 0) || (errno != EINTR)) {
      return false;
    }
  } while (true);
}
