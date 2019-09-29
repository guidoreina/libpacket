`libpacket`
==========
Library for working with PCAP files containing IP packets.

Only the following IP protocols are understood:
* TCP
* UDP
* ICMP
* ICMPv6


### Compiling the library
To compile the library just execute `make`.


### `class pcap::reader`
It can be used to iterate through the packets in a PCAP file (format is not understood).

Check `pcap_stats.cpp`

Start the program with:
```
LD_LIBRARY_PATH=. ./pcap_stats <filename>
```


### `class pcap::ip::analyzer`
It can be used to iterate through the IP packets in a PCAP file. It reassembles the fragmented packets.

Check `ip_stats.cpp`

Start the program with:
```
LD_LIBRARY_PATH=. ./ip_stats <filename>
```
