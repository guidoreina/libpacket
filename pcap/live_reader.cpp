#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include "pcap/live_reader.h"

bool pcap::live_reader::open(const char* filename)
{
  // Open file for reading.
  if ((_M_fd = ::open(filename, O_RDONLY)) != -1) {
    // If the buffer has not been allocated yet...
    if (!_M_buf) {
      // Allocate buffer.
      if ((_M_buf = static_cast<uint8_t*>(malloc(buffer_size))) != nullptr) {
        // Make '_M_bufend' point to the end of the buffer.
        _M_bufend = _M_buf + buffer_size;
      } else {
        return false;
      }
    }

    // Clear error.
    clearerr();

    // Reset pointer.
    _M_end = _M_buf;

    // Set state.
    _M_state = state::reading_file_header;

    return true;
  }

  return false;
}

bool pcap::live_reader::read(packet& pkt)
{
  do {
    switch (_M_state) {
      case state::reading_packet_data:
        // Read packet data.
        if (read_packet_data()) {
          pkt._M_data = _M_begin + sizeof(pkthdr);
          pkt._M_length = _M_record_length - sizeof(pkthdr);

          const pkthdr* const hdr = reinterpret_cast<const pkthdr*>(_M_begin);

          if (_M_resolution == resolution::microseconds) {
            pkt._M_timestamp = (hdr->ts.tv_sec * 1000000ull) + hdr->ts.tv_usec;
          } else {
            pkt._M_timestamp = (hdr->ts.tv_sec * 1000000ull) +
                               (hdr->ts.tv_usec / 1000);
          }

          // Make '_M_begin' point to the next record.
          _M_begin += _M_record_length;

          _M_state = state::reading_packet_header;

          return true;
        } else {
          return false;
        }

        break;
      case state::reading_packet_header:
        // Read packet header.
        if (read_packet_header()) {
          _M_state = state::reading_packet_data;
        } else {
          return false;
        }

        break;
      case state::reading_file_header:
      default:
        // Read file header.
        if (read_file_header()) {
          _M_state = state::reading_packet_header;
        } else {
          return false;
        }

        break;
    }
  } while (true);
}

bool pcap::live_reader::read_file_header()
{
  // Read from file.
  if (read()) {
    // Compute number of bytes in the buffer.
    const size_t len = _M_end - _M_buf;

    // If we have read the whole file header...
    if (len >= sizeof(file_header)) {
      // PCAP file?
      if (is_pcap()) {
        // Make '_M_begin' point to the first packet.
        _M_begin = _M_buf + sizeof(file_header);

        return true;
      } else {
        // Not a PCAP file.
        _M_error = true;
      }
    }
  }

  return false;
}

bool pcap::live_reader::read_packet_header()
{
  // If the packet header is not in the buffer...
  if (_M_begin + sizeof(pkthdr) > _M_end) {
    // If there is not so much space left in the buffer...
    if (_M_begin + sizeof(pkthdr) >= _M_bufend) {
      // Shift data to the left.
      shift_data_left();
    }

    // Read packet header.
    if ((!read()) ||
        (static_cast<size_t>(_M_end - _M_begin) < sizeof(pkthdr))) {
      return false;
    }
  }

  // Make 'hdr' point to the packet header.
  const pkthdr* const hdr = reinterpret_cast<const pkthdr*>(_M_begin);

  // Compute record length.
  _M_record_length = sizeof(pkthdr) + hdr->caplen;

  // Sanity check.
  if (_M_record_length <= buffer_size) {
    return true;
  } else {
    _M_error = true;

    return false;
  }
}

bool pcap::live_reader::read_packet_data()
{
  // If the packet is in the buffer...
  if (_M_begin + _M_record_length <= _M_end) {
    return true;
  } else {
    // If there is not so much space left in the buffer...
    if (_M_begin + _M_record_length > _M_bufend) {
      // Shift data to the left.
      shift_data_left();
    }

    // Read packet data.
    return ((read()) && (_M_end - _M_begin >= _M_record_length));
  }
}

bool pcap::live_reader::read()
{
  // Make 'end' point to the end of the data.
  const uint8_t* const end = _M_end;

  do {
    // Read from file.
    const ssize_t ret = ::read(_M_fd, _M_end, _M_bufend - _M_end);

    switch (ret) {
      default:
        if ((_M_end += ret) == _M_bufend) {
          return true;
        }

        break;
      case 0:
        _M_eof = true;
        return ((_M_end - end) > 0);
      case -1:
        if (errno != EINTR) {
          _M_error = true;
          return ((_M_end - end) > 0);
        }
    }
  } while (true);
}

void pcap::live_reader::shift_data_left()
{
  // Compute number of bytes in the buffer.
  const size_t len = _M_end - _M_begin;

  // If there is data in the buffer...
  if (len > 0) {
    // Move data to the beginning of the buffer.
    memmove(_M_buf, _M_begin, len);
  }

  _M_begin = _M_buf;
  _M_end = _M_buf + len;
}

bool pcap::live_reader::is_pcap()
{
  const file_header* const
    hdr = reinterpret_cast<const file_header*>(_M_buf);

  // Check magic.
  switch (static_cast<magic>(hdr->magic)) {
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
  if ((hdr->version_major == version_major) &&
      (hdr->version_minor == version_minor)) {
    // Save link-layer header type.
    _M_link_type = hdr->linktype;

    return true;
  }

  return false;
}
