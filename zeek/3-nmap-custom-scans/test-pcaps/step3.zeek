event connection_SYN_packet(c: connection, pkt: SYN_packet) {
	print c$id$orig_h, c$id$resp_h, c$id$resp_p, pkt$win_size, pkt$MSS, pkt$SACK_OK;
}
