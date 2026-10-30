@load base/frameworks/notice
@load base/protocols/http

module NmapSVScan;

export {
	redef enum Notice::Type += { Scan };
	# distinct ports, not connections: -sV only visits the few ports found open
	const threshold = 3 &redef;
}

# uids of connections that carried an HTTP request / a User-Agent header
global http_req: set[string];
global has_ua: set[string];

global probed: table[addr, addr] of set[port];
global notices: table[addr, addr] of count &default=0;

# NULL probe: the service spoke first (d) and the scanner never sent a byte (no D).
# Real FTP/SSH clients always answer the banner.
function is_banner_grab(history: string): bool {
	return starts_with(history, "S")
	    && "d" in history
	    && "D" !in history;
	}

# Nmap's HTTP probes (GetRequest, HTTPOptions, ...) carry no User-Agent, browsers always do.
event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) {
	add http_req[c$uid];
	}

event http_header(c: connection, is_orig: bool, original_name: string, name: string, value: string) {
	if (is_orig && name == "USER-AGENT")
		add has_ua[c$uid];
	}

# connection_state_remove: the connection is over, so c$history is final.
event connection_state_remove(c: connection) {
	local uid = c$uid;
	local bare_http = uid in http_req && uid !in has_ua;

	delete http_req[uid];
	delete has_ua[uid];

	if (!is_banner_grab(c$history) && !bare_http)
		return;

	local src = c$id$orig_h;
	local dst = c$id$resp_h;

	if ([src, dst] !in probed)
		probed[src, dst] = set();

	add probed[src, dst][c$id$resp_p];

	if (|probed[src, dst]| < threshold)
		return;

	NOTICE([$note=Scan,
	        $msg=fmt("Nmap version scan (-sV): %s grabbed banners or sent UA-less HTTP probes on %d ports of %s (previous notices for this scan: %d)",
	                 src, threshold, dst, notices[src, dst]),
	        $src=src,
	        $dst=dst]);

	++notices[src, dst];

	probed[src, dst] = set();
	}
