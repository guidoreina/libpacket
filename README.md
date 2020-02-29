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


### `class pcap::ip::tcp::connection::analyzer`
It can be used to iterate through the TCP connections in a PCAP file and extract the payloads.

Check `tcp_conns.cpp` and `extract_tcp_messages.cpp`

Start the programs with:
```
LD_LIBRARY_PATH=. ./tcp_conns <filename>
LD_LIBRARY_PATH=. ./extract_tcp_messages <filename> <directory>
```


### `class net::ip::dns::message`
DNS message parser.


### `class net::ip::tcp::streams`
It can be used to perform TCP reassembly.

Check `extract_streams.cpp`

Start the program with:
```
LD_LIBRARY_PATH=. ./extract_streams <filename> <directory>
```


### `class net::capture::ring_buffer`
It can be used to read packets from the network card using PACKET\_MMAP (ring buffer).

Check `capture.cpp`

Start the program with:
```
LD_LIBRARY_PATH=. ./capture <interface-name>
```


### `class net::ip::services`
Class for working with IP services.

An IP service has an identifier, a name and a list of IP addresses and/or domains.

The class loads the services from a directory (one file per service).

Filenames have the format:
```
<service-id>_<service-name>.svc
<service-id> ::= <number>
```

Each service file contains lines with the following format:
```
<ip-address-or-domain>[,<from-port>[,<to-port>]]
<ip-address-or-domain> ::= <ip-address> | <domain>
<ip-address> ::= <ipv4-address-or-ipv6-address>[/<prefix-length>]
<ipv4-address-or-ipv6-address> ::= <ipv4-address> | <ipv6-address>
<from-port> ::= <port>
<to-port> ::= <port>
<prefix-length> ::= 1 .. 32 (for IPv4 addresses) |
                    1 .. 128 (for IPv6 addresses)
```

Check `test_services.cpp`

Start the program with:
```
LD_LIBRARY_PATH=. ./test_services <directory> <pcap-file>
```


### `service`
Program which takes two arguments, a directory containing services and an IP address and returns the service to which the IP address belongs to.


### `services_to_pcap`
Generates a PCAP file for each service contained in a PCAP file.

Start the program with:
```
LD_LIBRARY_PATH=. ./services_to_pcap <services-directory> <pcap-file> <output-directory>
```


### `statistics`
Generates IP and service statistics. It can also generate a PCAP file per service.

Start the program with:
```
./statistics --services-directory <directory> --pcap <filename> [--csv-directory <directory>] [--pcap-directory <directory>]
```
