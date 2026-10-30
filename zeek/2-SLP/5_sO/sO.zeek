@load base/frameworks/notice

module NmapSOScan;

export {
	redef enum Notice::Type += { Scan };
	# distinct IP protocol numbers per [src, dst]
	const threshold = 20 &redef;
}

# -sO walks the 8-bit IP protocol field (0-255) instead of ports: one bare IP packet
# per protocol number. A normal host talks to another with 1-3 protocols (ICMP, TCP,
# UDP), so many DIFFERENT protocol numbers from one source to one target is the signal.
#
# In Zeek 9 (our container) every IP protocol gets a connection, and c$id$proto holds its number
# (unknown ones show up as "unknown_transport" in conn.log), so new_connection is enough:
# no need for raw_packet, which runs script code on every single packet.
# Blind spot: 2 (IGMP), 4, 41, 47 (tunnels), 58, 59, 255 never become connections,
# so a full -sO is seen as ~249 protocols instead of 256.
#
# The ICMP "protocol unreachable" replies (type 3, code 2) are NOT used, unlike sU:
# Nmap's probe is a bare 20-byte IP header, so the copy quoted inside the ICMP error
# has no transport header, Zeek marks it bad_hdr_len and leaves context$proto = 0.
# The reply tells us "some protocol was refused" but not which one.
#
# Like sU, the set is never reset: a Notice means "`threshold` NEW protocols", so a
# retransmitted probe (a new connection for a protocol already seen) is not re-counted.
global seen: table[addr, addr] of set[count];
global new_protos: table[addr, addr] of count &default=0;
global notices: table[addr, addr] of count &default=0;

event new_connection(c: connection) {
	local src = c$id$orig_h;
	local dst = c$id$resp_h;
	local proto = c$id$proto;

	if ([src, dst] !in seen)
		seen[src, dst] = set();

	if (proto in seen[src, dst])
		return;

	add seen[src, dst][proto];
	++new_protos[src, dst];

	if (new_protos[src, dst] < threshold)
		return;

	NOTICE([$note=Scan,
	        $msg=fmt("Nmap IP protocol scan (-sO): %s sent %d new IP protocol numbers to %s (previous notices for this scan: %d)",
	                 src, threshold, dst, notices[src, dst]),
	        $src=src,
	        $dst=dst]);

	++notices[src, dst];

	new_protos[src, dst] = 0;
	}
