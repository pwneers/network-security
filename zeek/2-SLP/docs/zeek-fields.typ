// Compile from the repo root so the report library can be imported:
//   typst compile --root . zeek/2-SLP/docs/zeek-fields.typ
#import "../../../report/lib.typ": *

// Same page, text and heading style as the report, without the cover page.
#set page(
  paper: "a4",
  margin: (top: 20mm, bottom: 20mm, left: 20mm, right: 20mm),
  footer: context [
    #set text(size: 8pt, fill: pwneers-muted)
    #line(length: 100%, stroke: 0.5pt + pwneers-border)
    #v(0.35em)
    Pwneers: Zeek fields - page #counter(page).display()
  ],
)
#set text(font: "Calibre", size: 10.5pt, fill: pwneers-ink, lang: "en")
#set par(leading: 0.65em)
#set heading(numbering: "1.1")

#show raw: set text(font: "JetBrainsMono NF", size: 8.8pt, fill: pwneers-primary)

#show heading.where(level: 1): it => {
  show raw: set text(fill: white)
  v(0.9em)
  block(
    width: 100%,
    inset: (left: 0.8em, top: 0.45em, bottom: 0.45em),
    fill: pwneers-primary,
    radius: 3pt,
  )[
    #text(size: 14pt, weight: "bold", fill: white)[
      #if it.numbering != none {
        counter(heading).display(it.numbering)
        h(0.55em)
      }
      #it.body
    ]
  ]
  v(0.45em)
}

#show heading.where(level: 2): it => {
  v(0.65em)
  text(size: 12pt, weight: "bold", fill: pwneers-primary)[
    #counter(heading).display(it.numbering)
    #h(0.45em)
    #it.body
  ]
  line(length: 100%, stroke: 0.8pt + pwneers-accent-light)
  v(0.25em)
}

#let fields(..rows) = simple-table(
  ([Field], [Type], [Meaning]),
  rows.pos(),
  columns: (auto, auto, 1fr),
)

#align(center)[
  #text(size: 24pt, weight: "bold", fill: pwneers-primary)[Zeek Fields Cheat Sheet]
  #v(0.2em)
  #text(size: 12pt, fill: pwneers-accent)[Zeek 9.0.1 - records and events for scan detection]
]
#v(0.6em)

#callout(title: "Optional fields")[
  Fields marked `optional` may be missing: check with `x?$field` before reading `x$field`.
]

#show outline.entry.where(level: 1): set text(weight: "bold")
#outline(title: [Contents], depth: 2)
#pagebreak()

= Events
#simple-table(
  ([Event], [Arguments / when]),
  (
    [`connection_SYN_packet`], [`c: connection, pkt: SYN_packet` - every SYN],
    [`tcp_packet`], [`c, is_orig: bool, flags: string, seq, ack, len: count, payload: string` - every TCP packet],
    [`new_packet`], [`c, p: pkt_hdr` - every packet (slow)],
    [`raw_packet`], [`p: raw_pkt_hdr` - every packet, no connection],
    [`new_connection`], [`c`],
    [`connection_established`], [`c` - full handshake seen],
    [`connection_attempt`], [`c` - SYN with no answer],
    [`connection_rejected`], [`c` - SYN answered with RST],
    [`connection_reset`], [`c`],
    [`connection_half_finished`], [`c`],
    [`connection_first_ACK`], [`c`],
    [`connection_state_remove`], [`c` - connection over, `c$history` is final],
    [`udp_request` / `udp_reply`], [`u: connection`],
    [`icmp_echo_request`], [`c, info: icmp_info, id, seq: count, payload: string`],
    [`icmp_unreachable` / `icmp_time_exceeded`], [`c, info: icmp_info, code: count, context: icmp_context`],
  ),
  columns: (auto, 1fr),
)

= `pkt: SYN_packet`
#fields(
  [`pkt$is_orig`], [bool], [T if the originator sent it],
  [`pkt$DF`], [bool], [IP "don't fragment" bit set],
  [`pkt$ttl`], [count], [IP time-to-live],
  [`pkt$size`], [count], [payload size from IP header],
  [`pkt$win_size`], [count], [TCP window size],
  [`pkt$win_scale`], [int], [window-scale option, -1 if missing],
  [`pkt$MSS`], [count], [max segment size option, 0 if missing],
  [`pkt$SACK_OK`], [bool], [SACK-permitted option present],
  [`pkt$TSval` / `pkt$TSecr`], [count, optional], [TCP timestamp value / echo reply],
)

= `c: connection`
#fields(
  [`c$id$orig_h` / `orig_p`], [addr / port], [originator IP / port],
  [`c$id$resp_h` / `resp_p`], [addr / port], [responder IP / port],
  [`c$id$proto`], [count], [6 = TCP, 17 = UDP, 1 = ICMP],
  [`c$uid`], [string], [connection ID (as in the logs)],
  [`c$start_time`], [time], [first packet timestamp],
  [`c$duration`], [interval], [connection duration],
  [`c$service`], [set[string]], [detected protocols, e.g. `"http"`],
  [`c$history`], [string], [state history (see below)],
  [`c$orig$size` / `c$resp$size`], [count], [bytes sent],
  [`c$orig$state` / `c$resp$state`], [count], [`TCP_INACTIVE`, `TCP_SYN_SENT`, `TCP_SYN_ACK_SENT`, `TCP_PARTIAL`, `TCP_ESTABLISHED`, `TCP_CLOSED`, `TCP_RESET`, `UDP_ACTIVE`, `UDP_INACTIVE`],
  [`c$orig$num_pkts`], [count, optional], [packets sent],
  [`c$orig$num_bytes_ip`], [count, optional], [IP-level bytes sent],
  [`c$orig$l2_addr`], [string, optional], [MAC address],
)

== `c$history` letters
Uppercase = originator, lowercase = responder.
#simple-table(
  ([Letter], [Meaning], [Letter], [Meaning]),
  (
    [`S`], [SYN without ACK], [`H`], [SYN+ACK],
    [`A`], [pure ACK], [`D`], [packet with payload],
    [`F`], [FIN], [`R`], [RST],
    [`C`], [bad checksum], [`G`], [content gap],
    [`T`], [retransmission], [`W`], [zero window],
    [`I`], [inconsistent packet (e.g. SYN+RST)], [`Q`], [multi-flag packet (SYN+FIN, SYN+RST)],
    [`^`], [originator/responder swapped], [], [],
  ),
  columns: (auto, 1fr, auto, 1fr),
)

= `tcp_packet` arguments
#fields(
  [`is_orig`], [bool], [T if the originator sent it],
  [`flags`], [string], [flags as letters: `"S"`, `"SA"`, `"F"`, `"FPU"`, `"R"`, `"A"`, `""` = none],
  [`seq` / `ack`], [count], [sequence / ack numbers],
  [`len`], [count], [payload length],
  [`payload`], [string], [the payload],
)

= `p: pkt_hdr` (from `new_packet`)
#callout(title: "Check first")[
  `p$ip`, `p$ip6`, `p$tcp`, `p$udp`, `p$icmp` are optional: test `p?$tcp` first.
]

== `p$ip` (ip4_hdr)
#fields(
  [`hl`], [count], [header length],
  [`tos`], [count], [type of service],
  [`len`], [count], [total length],
  [`id`], [count], [IP ID],
  [`DF` / `MF`], [bool], [don't-fragment / more-fragments bits],
  [`offset`], [count], [fragment offset],
  [`ttl`], [count], [time-to-live],
  [`p`], [count], [protocol number],
  [`sum`], [count], [checksum],
  [`src` / `dst`], [addr], [source / destination address],
)

== `p$tcp` (tcp_hdr)
#fields(
  [`sport` / `dport`], [port], [source / destination port],
  [`seq` / `ack`], [count], [sequence / ack numbers],
  [`hl`], [count], [header length],
  [`dl`], [count], [data length],
  [`reserved`], [count], [the 4 reserved bits],
  [`win`], [count], [window size],
  [`flags`], [count], [bitmask: FIN=1, SYN=2, RST=4, PSH=8, ACK=16, URG=32 (0 = no flags)],
)

== `p$udp` (udp_hdr) and `p$icmp` (icmp_hdr)
#fields(
  [`sport` / `dport`], [port], [source / destination port],
  [`ulen`], [count], [UDP length],
  [`icmp_type`], [count], [ICMP type],
)

= ICMP records
== `info: icmp_info`
#fields(
  [`v6`], [bool], [T if ICMPv6],
  [`itype` / `icode`], [count], [ICMP type / code],
  [`len`], [count], [ICMP payload length],
  [`ttl`], [count], [TTL of the outer IP header],
)

== `context: icmp_context`
The original packet quoted inside an ICMP error.
#fields(
  [`id`], [conn_id], [quoted packet's 4-tuple (`context$id$resp_p` = probed port)],
  [`proto`], [count], [quoted packet's protocol],
  [`len`], [count], [quoted packet's length],
  [`frag_offset`], [count], [fragment offset],
  [`MF` / `DF`], [bool], [fragment bits],
  [`bad_hdr_len`], [bool], [quoted header too short to read],
  [`bad_checksum`], [bool], [IP checksum wrong],
)
