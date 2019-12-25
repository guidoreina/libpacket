#include "pcap/ip/tcp/connection/analyzer.h"
#include "net/ip/tcp/flags.h"

const net::ip::tcp::message*
pcap::ip::tcp::connection::analyzer::
const_iterator::message(ip::analyzer& analyzer,
                        net::ip::tcp::direction dir,
                        net::ip::tcp::message* msg)
{
  // Maximum gap size.
  static constexpr const size_t max_gap_size = 1 * 1024ul * 1024ul;

  _M_connection.state(net::ip::tcp::connection::state::data_transfer);

  // Set timestamp of the last packet.
  _M_connection.touch(_M_it_ack->timestamp());

  // Get IP version.
  const net::ip::version ip_version = syn()->version();

  // Get initial sequence number.
  uint32_t seq = (dir == net::ip::tcp::direction::from_client) ?
                   ntohl(ack()->tcp()->seq) :
                   ntohl(ack()->tcp()->ack_seq);

  size_t offset = 0;

  ip::analyzer::const_iterator it = _M_it_ack;

  // While the connection has not been closed and there are packets...
  while (((_M_connection.state() ==
           net::ip::tcp::connection::state::data_transfer) ||
          (_M_connection.state() ==
           net::ip::tcp::connection::state::closing)) &&
         (analyzer.next(net::ip::protocol::tcp, it))) {
    // If the IP versions match...
    if (ip_version == it->version()) {
      const struct tcphdr* const tcphdr = it->tcp();

      net::ip::tcp::direction pktdir;

      // IPv4?
      if (ip_version == net::ip::version::v4) {
        if (!_M_connection.match(it->ipv4(), tcphdr, pktdir)) {
          continue;
        }
      } else {
        if (!_M_connection.match(it->ipv6(), tcphdr, pktdir)) {
          continue;
        }
      }

      // Process packet.
      if (_M_connection.process(dir, tcphdr->th_flags, it->timestamp())) {
        // If the current packet has the expected direction...
        if (pktdir == dir) {
          // If the current packet has payload...
          if (it->has_payload()) {
            // Save packet's sequence number.
            const uint32_t tcphdrseq = ntohl(tcphdr->seq);

            // If the current packet doesn't have the next sequence number...
            if (tcphdrseq != seq) {
              uint32_t diff = tcphdrseq - seq;

              // If there is a gap...
              if (diff <= max_gap_size) {
                offset += diff;
              } else {
                diff = seq - tcphdrseq;

                // If the segment is old...
                if ((diff <= max_gap_size) && (offset >= diff)) {
                  offset -= diff;
                } else {
                  // Ignore TCP segment.
                  continue;
                }
              }
            }

            // Append payload to the message.
            if (msg->pwrite(it->l4(), it->l4length(), offset)) {
              // Set sequence number.
              seq = tcphdrseq + it->l4length();

              // Increment offset.
              offset += it->l4length();
            } else {
              return nullptr;
            }
          }
        }
      } else {
        break;
      }
    }
  }

  return msg->finish(_M_it_syn->timestamp()) ? msg : nullptr;
}

bool pcap::ip::tcp::connection::analyzer::begin(const_iterator& it)
{
  // Find first TCP segment.
  if (_M_analyzer.begin(net::ip::protocol::tcp, it._M_it_syn)) {
    do {
      if ((find_syn(it)) && (find_syn_ack(it)) && (find_ack(it))) {
        return true;
      }
    } while (_M_analyzer.next(net::ip::protocol::tcp, it._M_it_syn));
  }

  return false;
}

bool pcap::ip::tcp::connection::analyzer::next(const_iterator& it)
{
  // Find next TCP segment.
  while (_M_analyzer.next(net::ip::protocol::tcp, it._M_it_syn)) {
    if ((find_syn(it)) && (find_syn_ack(it)) && (find_ack(it))) {
      return true;
    }
  }

  return false;
}

bool pcap::ip::tcp::connection::analyzer::find_syn(const_iterator& it)
{
  do {
    // SYN segment?
    if ((it._M_it_syn->tcp()->th_flags & net::ip::tcp::flag_mask) ==
        net::ip::tcp::syn) {
      // Initialize TCP connection.
      if (it._M_it_syn->version() == net::ip::version::v4) {
        it._M_connection.assign(it._M_it_syn->ipv4(),
                                it._M_it_syn->tcp(),
                                net::ip::tcp::direction::from_client,
                                net::ip::tcp::connection::
                                  state::connection_requested,
                                it._M_it_syn->timestamp());
      } else {
        it._M_connection.assign(it._M_it_syn->ipv6(),
                                it._M_it_syn->tcp(),
                                net::ip::tcp::direction::from_client,
                                net::ip::tcp::connection::
                                  state::connection_requested,
                                it._M_it_syn->timestamp());
      }

      return true;
    }
  } while (_M_analyzer.next(net::ip::protocol::tcp, it._M_it_syn));

  return false;
}

bool pcap::ip::tcp::connection::analyzer::find_syn_ack(const_iterator& it)
{
  // Make 'it._M_it_syn_ack' point to the same packet as 'it._M_it_syn'.
  it._M_it_syn_ack = it._M_it_syn;

  // Save IP version.
  const net::ip::version ip_version = it._M_it_syn->version();

  // Find SYN + ACK.
  while ((_M_analyzer.next(net::ip::protocol::tcp, it._M_it_syn_ack)) &&
         ((it._M_it_syn_ack->timestamp() < it._M_it_syn->timestamp()) ||
          (it._M_it_syn_ack->timestamp() - it._M_it_syn->timestamp() <=
           max_delay * 1000000ull))) {
    // If the IP versions match...
    if (ip_version == it._M_it_syn_ack->version()) {
      net::ip::tcp::direction dir;

      // IPv4?
      if (ip_version == net::ip::version::v4) {
        if (!it._M_connection.match(it._M_it_syn_ack->ipv4(),
                                    it._M_it_syn_ack->tcp(),
                                    dir)) {
          continue;
        }
      } else {
        if (!it._M_connection.match(it._M_it_syn_ack->ipv6(),
                                    it._M_it_syn_ack->tcp(),
                                    dir)) {
          continue;
        }
      }

      // Process packet.
      if (it._M_connection.process(dir,
                                   it._M_it_syn_ack->tcp()->th_flags,
                                   it._M_it_syn_ack->timestamp())) {
        switch (it._M_connection.state()) {
          case net::ip::tcp::connection::state::connection_established:
            return (ntohl(it._M_it_syn_ack->tcp()->ack_seq) ==
                    static_cast<uint32_t>(ntohl(it._M_it_syn->tcp()->seq) + 1));
          case net::ip::tcp::connection::state::connection_requested:
            break;
          default:
            return false;
        }
      } else {
        return false;
      }
    }
  }

  return false;
}

bool pcap::ip::tcp::connection::analyzer::find_ack(const_iterator& it)
{
  // Make 'it._M_it_ack' point to the same packet as 'it._M_it_syn_ack'.
  it._M_it_ack = it._M_it_syn_ack;

  // Save IP version.
  const net::ip::version ip_version = it._M_it_syn->version();

  // Find ACK.
  while ((_M_analyzer.next(net::ip::protocol::tcp, it._M_it_ack)) &&
         ((it._M_it_ack->timestamp() < it._M_it_syn_ack->timestamp()) ||
          (it._M_it_ack->timestamp() - it._M_it_syn_ack->timestamp() <=
           max_delay * 1000000ull))) {
    // If the IP versions match...
    if (ip_version == it._M_it_ack->version()) {
      net::ip::tcp::direction dir;

      // IPv4?
      if (ip_version == net::ip::version::v4) {
        if (!it._M_connection.match(it._M_it_ack->ipv4(),
                                    it._M_it_ack->tcp(),
                                    dir)) {
          continue;
        }
      } else {
        if (!it._M_connection.match(it._M_it_ack->ipv6(),
                                    it._M_it_ack->tcp(),
                                    dir)) {
          continue;
        }
      }

      // Process packet.
      if (it._M_connection.process(dir,
                                   it._M_it_ack->tcp()->th_flags,
                                   it._M_it_ack->timestamp())) {
        switch (it._M_connection.state()) {
          case net::ip::tcp::connection::state::data_transfer:
            return ((ntohl(it._M_it_ack->tcp()->ack_seq) ==
                     static_cast<uint32_t>(
                       ntohl(it._M_it_syn_ack->tcp()->seq) + 1
                     )) &&
                    (it._M_it_ack->tcp()->seq ==
                     it._M_it_syn_ack->tcp()->ack_seq));
          case net::ip::tcp::connection::state::connection_established:
            break;
          default:
            return false;
        }
      } else {
        return false;
      }
    }
  }

  return false;
}
