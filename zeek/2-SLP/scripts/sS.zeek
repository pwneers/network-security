@load base/frameworks/notice

module NmapSynScan;

export {
	redef enum Notice::Type += { Scan };

	const threshold = 100 &redef;
}

global probed: table[addr, addr] of set[port];

global notices: table[addr, addr] of count &default=0;

function is_nmap_syn(pkt: SYN_packet): bool {
	return pkt$win_size <= 4096      # small window (Nmap: 1024)
	    && pkt$MSS > 0               # has the MSS option...
	    && ! pkt$SACK_OK             # ...but no SACK option,
	    && pkt$win_scale == -1       # no window-scale option (-1 = absent),
	    && ! pkt?$TSval;             # and no timestamp option (`?$` = "is present?")
	}

event connection_SYN_packet(c: connection, pkt: SYN_packet) {
	if ( ! pkt$is_orig )
		return;

	if ( ! is_nmap_syn(pkt) )
		return;

	local src = c$id$orig_h;
	local dst = c$id$resp_h;

	if ( [src, dst] !in probed )
		probed[src, dst] = set();

	add probed[src, dst][c$id$resp_p];

	if ( |probed[src, dst]| < threshold )
		return;

	NOTICE([$note=Scan,
	        $msg=fmt("Nmap SYN scan (-sS): %s sent Nmap-crafted SYNs to %d ports of %s (previous notices for this scan: %d)",
	                 src, threshold, dst, notices[src, dst]),
	        $src=src,
	        $dst=dst]);

	++notices[src, dst];

	probed[src, dst] = set();
	}
