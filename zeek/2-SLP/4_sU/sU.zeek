@load base/frameworks/notice

module NmapSUScan;

export {
	redef enum Notice::Type += { Scan };
	# distinct UDP ports per [src, dst]
	const threshold = 20 &redef;
}

# Unlike sS/sT, the port set is NEVER reset: a Notice means "`threshold` NEW ports".
# UDP has no handshake, so Nmap retransmits every probe that gets no answer
# (in the pcap: 229 probes for 83 ports, one port probed 34 times), and the ICMP
# replies arrive late. With a reset after each Notice, those retries and late
# ICMPs re-count ports already seen: 10 Notices for only 83 ports (10 x 20 > 83).
# Remembering every port gives 83 / 20 = 4 Notices, one per 20 really new ports.
# Trade-off: a second -sU of the same ports adds nothing new, so it raises no new
# Notice (fine here: the pcap holds a single UDP scan).
global seen: table[addr, addr] of set[port];
global new_ports: table[addr, addr] of count &default=0;
global notices: table[addr, addr] of count &default=0;

# Both signals end up here: count the port if it is new, raise a Notice every `threshold` new ports.
function add_probe(src: addr, dst: addr, p: port) {
	if ([src, dst] !in seen)
		seen[src, dst] = set();

	# retransmission or the ICMP reply to a port already counted
	if (p in seen[src, dst])
		return;

	add seen[src, dst][p];
	++new_ports[src, dst];

	if (new_ports[src, dst] < threshold)
		return;

	NOTICE([$note=Scan,
	        $msg=fmt("Nmap UDP scan (-sU): %s probed %d new UDP ports of %s (previous notices for this scan: %d)",
	                 src, threshold, dst, notices[src, dst]),
	        $src=src,
	        $dst=dst]);

	++notices[src, dst];

	new_ports[src, dst] = 0;
	}

# Signal 1: Nmap's default UDP probe is an empty datagram (28 bytes = IP + UDP header).
# Real UDP protocols (DNS, NTP, NetBIOS, ...) always carry a payload.
# connection_state_remove: the "connection" is over, so c$orig$size (payload bytes) is final.
event connection_state_remove(c: connection) {
	if (get_port_transport_proto(c$id$resp_p) != udp)
		return;

	if (c$orig$size != 0)
		return;

	add_probe(c$id$orig_h, c$id$resp_h, c$id$resp_p);
	}

# Signal 2: the target answers a probe to a closed UDP port with ICMP port unreachable (type 3, code 3).
# `context` is the header of the original datagram quoted inside the ICMP error, so it names the scanner.
# This also catches Nmap's payload probes (DNS, NTP, SNMP, ...) that signal 1 misses.
event icmp_unreachable(c: connection, info: icmp_info, code: count, context: icmp_context) {
	if (code != 3)
		return;

	if (get_port_transport_proto(context$id$resp_p) != udp)
		return;

	add_probe(context$id$orig_h, context$id$resp_h, context$id$resp_p);
	}
