# -sO (IP protocol scan)

## No -sO scan in the assignment pcap
`assignment_lecture10.pcap` contains **no -sO scan**: `sO.zeek` raises 0 notices there, so Zeek writes no `notice.log`.
The only uncommon protocols from `172.16.0.1` are IGMP and SCTP (62 packets each). They are Nmap **host discovery**
(`-PO` IGMP query, `-PY` SCTP INIT to port 80, plus `-PU` empty UDP to port 40125), repeated ~31 times:
5 protocols in total, against ~256 for a real -sO. The target never sends an ICMP protocol unreachable (type 3, code 2).

## Tested on a "fake" pcap
To still test the script we captured our own -sO scan: `sO.pcap` in this folder
(`127.0.0.1` → `127.0.0.2` over loopback, 255 protocols, 32 KB).
The `notice.log` in this folder comes from it: 12 notices (~249 protocols seen / threshold 20).

```sh
# from 2-SLP/
zeek -C -r 5_sO/sO.pcap 5_sO/sO.zeek
```
