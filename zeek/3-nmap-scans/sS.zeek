##! Detects Nmap TCP SYN scans (nmap -sS).
##!
##! Idea: with -sS, Nmap does not ask the operating system to connect.
##! It builds the SYN packet by hand, and that hand-made SYN has a
##! fingerprint a normal OS never produces:
##!   - small TCP window (Nmap uses 1024),
##!   - only the MSS option: no SACK, no timestamps, no window scale.
##! We count how many DISTINCT ports a scanner sends such SYNs to on one
##! target. When the count reaches `threshold` we raise a Notice and the
##! count starts over from zero.

# Gives us NOTICE() and notice.log (normally loaded already, but explicit is clearer).
@load base/frameworks/notice

# Everything below lives in the "NmapSynScan" namespace, so names like
# `threshold` don't clash with other scripts (e.g. the -sT one).
module NmapSynScan;

# Things in `export` are visible from outside this script.
export {
	# Declare our own notice type. In notice.log it shows up as
	# "NmapSynScan::Scan".
	redef enum Notice::Type += { Scan };

	# How many distinct ports before a Notice is raised.
	# `&redef` lets you change it from the command line, e.g.:
	#   zeek -C -r file.pcap sS.zeek NmapSynScan::threshold=50
	const threshold = 100 &redef;
}

# For each (scanner, target) pair: the set of ports probed since the last
# Notice. A set ignores duplicates, so Nmap's re-sent SYNs count only once.
global probed: table[addr, addr] of set[port];

# For each (scanner, target) pair: how many Notices we already raised.
# `&default=0` means an unknown pair reads as 0 instead of giving an error.
global notices: table[addr, addr] of count &default=0;

# Returns T if this SYN looks hand-made by Nmap, F if it looks like a
# normal SYN from an operating system.
function is_nmap_syn(pkt: SYN_packet): bool
	{
	return pkt$win_size <= 4096      # small window (Nmap: 1024)
	    && pkt$MSS > 0               # has the MSS option...
	    && ! pkt$SACK_OK             # ...but no SACK option,
	    && pkt$win_scale == -1       # no window-scale option (-1 = absent),
	    && ! pkt?$TSval;             # and no timestamp option (`?$` = "is present?")
	}

# Zeek calls this for every SYN packet it sees.
event connection_SYN_packet(c: connection, pkt: SYN_packet)
	{
	# The target's SYN/ACK also triggers this event: skip it.
	# We only want the scanner's SYN (the "originator" of the connection).
	if ( ! pkt$is_orig )
		return;

	# Skip normal SYNs (browsers, ssh, nmap -sT, ...).
	if ( ! is_nmap_syn(pkt) )
		return;

	local src = c$id$orig_h;    # scanner IP
	local dst = c$id$resp_h;    # target IP

	# First Nmap SYN from this scanner to this target: create an empty set.
	if ( [src, dst] !in probed )
		probed[src, dst] = set();

	# Remember the probed port (e.g. 80/tcp).
	add probed[src, dst][c$id$resp_p];

	# Not enough ports yet: wait for more SYNs.
	if ( |probed[src, dst]| < threshold )
		return;

	# Threshold reached: raise the Notice. The message uses the number of
	# Notices raised BEFORE this one, so we read it before increasing it.
	# (No $identifier on purpose: it would make Zeek suppress repeated Notices.)
	NOTICE([$note=Scan,
	        $msg=fmt("Nmap SYN scan (-sS): %s sent Nmap-crafted SYNs to %d ports of %s (previous notices for this scan: %d)",
	                 src, threshold, dst, notices[src, dst]),
	        $src=src,
	        $dst=dst]);

	# One more Notice for this pair...
	++notices[src, dst];

	# ...and the count starts over.
	probed[src, dst] = set();
	}
