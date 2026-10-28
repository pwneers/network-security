##! Unified Nmap scan detection -- SLP Assignment 10.2.
##!
##! ONE script, but EACH scan type keeps its OWN pair of state tables and its
##! OWN Notice type. Sharing a single counter across scans would mix them
##! together and break the required "number of previous Notices for the SAME
##! scan" figure, so every scan gets:
##!   <scan>_count   : probes counted SINCE the last Notice (reset on fire)
##!   <scan>_notices : how many Notices already raised (never reset)
##!
##! Detection model (same for every scan): a single stray probe is normal
##! traffic, so we detect by VOLUME -- count a scan's probes per source IP and
##! raise a Notice every `threshold` probes, then start over. Lower threshold
##! => more Notices. Threshold is chosen by the group and is &redef-able.
##!
##! How each probe is recognised:
##!   -sS  SYN sent, handshake NEVER completed       -> history '^S' and no 'A'
##!   -sT  handshake completed, scanner sent NO data -> history 'A', no 'D'
##!   -sV  completed connection WITH scanner data    -> history 'A' and 'D'
##!   -sU  UDP datagram to a port                    -> transport is udp
##!   -sO  IP packet with an exotic protocol number  -> ip proto not 1/6/17
##!        (handled at PACKET level in raw_packet, see bottom)
##!
##! (-sR is discussed in the SLP but not scripted: it probes SunRPC/portmapper,
##!  and the victim here exposes no RPC service, so -sR leaves no distinctive
##!  traffic to detect -- the live confirmation of its minimal footprint.)

module NmapScan;

export {
	redef enum Notice::Type += {
		SYN_Scan,        # -sS
		Connect_Scan,    # -sT
		UDP_Scan,        # -sU
		Version_Scan,    # -sV
		Proto_Scan,      # -sO
	};

	# One threshold per scan, chosen by the group (&redef to tune on the CLI,
	# e.g. -e 'NmapScan::syn_threshold=100').
	const syn_threshold     = 20 &redef;
	const connect_threshold = 20 &redef;
	const udp_threshold     = 20 &redef;
	const version_threshold = 20 &redef;
	const proto_threshold   = 20 &redef;
}

# ------------------------- per-scan state tables --------------------------
# -sS
global syn_count:       table[addr] of count &default=0;
global syn_notices:     table[addr] of count &default=0;
# -sT
global connect_count:   table[addr] of count &default=0;
global connect_notices: table[addr] of count &default=0;
# -sU
global udp_count:       table[addr] of count &default=0;
global udp_notices:     table[addr] of count &default=0;
# -sV
global version_count:   table[addr] of count &default=0;
global version_notices: table[addr] of count &default=0;
# -sO
global proto_count:     table[addr] of count &default=0;
global proto_notices:   table[addr] of count &default=0;

# TCP/UDP scans: this event fires once per connection, when Zeek is done.
event connection_state_remove(c: connection)
	{
	local scanner = c$id$orig_h;

	# ---- -sS : SYN sent, handshake never completed (no originator ACK) ----
	if ( /^S/ in c$history && "A" !in c$history )
		{
		++syn_count[scanner];
		if ( syn_count[scanner] >= syn_threshold )
			{
			NOTICE([$note=SYN_Scan, $src=scanner,
			        $msg=fmt("Nmap SYN (-sS) scan from %s: %d uncompleted SYN probes reached threshold %d (previous Notices for this scan: %d)",
			                 scanner, syn_count[scanner], syn_threshold,
			                 syn_notices[scanner])]);
			++syn_notices[scanner];
			syn_count[scanner] = 0;
			}
		}

	# ---- -sT : handshake completed ('A') but scanner sent no data ('D') ----
	else if ( /^S/ in c$history && "A" in c$history && "D" !in c$history )
		{
		++connect_count[scanner];
		if ( connect_count[scanner] >= connect_threshold )
			{
			NOTICE([$note=Connect_Scan, $src=scanner,
			        $msg=fmt("Nmap connect (-sT) scan from %s: %d completed empty connections reached threshold %d (previous Notices for this scan: %d)",
			                 scanner, connect_count[scanner], connect_threshold,
			                 connect_notices[scanner])]);
			++connect_notices[scanner];
			connect_count[scanner] = 0;
			}
		}

	# ---- -sU : UDP scan  --------------------------------------------------
	else if ( get_port_transport_proto(c$id$resp_p) == udp )
		{
		++udp_count[scanner];
		if ( udp_count[scanner] >= udp_threshold )
			{
			NOTICE([$note=UDP_Scan, $src=scanner,
			        $msg=fmt("Nmap UDP (-sU) scan from %s: %d UDP probes reached threshold %d (previous Notices for this scan: %d)",
			                 scanner, udp_count[scanner], udp_threshold,
			                 udp_notices[scanner])]);
			++udp_notices[scanner];
			udp_count[scanner] = 0;
			}
		}

	# ---- -sV : version scan  ----------------------------------------------
	else if ( /^S/ in c$history && "A" in c$history && "D" in c$history )
		{
		++version_count[scanner];
		if ( version_count[scanner] >= version_threshold )
			{
			NOTICE([$note=Version_Scan, $src=scanner,
			        $msg=fmt("Nmap version (-sV) scan from %s: %d completed data connections reached threshold %d (previous Notices for this scan: %d)",
			                 scanner, version_count[scanner], version_threshold,
			                 version_notices[scanner])]);
			++version_notices[scanner];
			version_count[scanner] = 0;
			}
		}
	}

# ---- -sO : IP protocol scan (packet level) --------------------------------
event raw_packet(pkt: raw_pkt_hdr)
	{
	# Only IPv4 packets carry the protocol number we test.
	if ( ! pkt?$ip )
		return;

	local pr = pkt$ip$p;                       # IP protocol number
	if ( pr == 1 || pr == 6 || pr == 17 )      # ICMP / TCP / UDP: not -sO
		return;

	local scanner = pkt$ip$src;
	++proto_count[scanner];
	if ( proto_count[scanner] >= proto_threshold )
		{
		NOTICE([$note=Proto_Scan, $src=scanner,
		        $msg=fmt("Nmap IP-protocol (-sO) scan from %s: %d exotic-protocol packets reached threshold %d (previous Notices for this scan: %d)",
		                 scanner, proto_count[scanner], proto_threshold,
		                 proto_notices[scanner])]);
		++proto_notices[scanner];
		proto_count[scanner] = 0;
		}
	}
