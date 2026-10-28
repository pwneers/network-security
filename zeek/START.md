# Start

## 1. Start the container

```sh
docker compose up -d --build    # build + start (only slow the first time)
docker compose exec zeek bash   # shell inside the container
```

This folder is mounted at `/work`, so files created inside appear here too.

Stop it with `docker compose stop` (start again with `docker compose start`).

## 2. Run Zeek on a pcap

Run it from the folder where you want the `.log` files:

```sh
cd 1-lecture-pcaps
zeek -C -r assignment_lecture10.pcap    # -C = ignore bad checksums
ls *.log                                # conn.log, dns.log, http.log, ...
```

## 3. Read logs with zeek-cut

```sh
head conn.log                                          # see the #fields header
zeek-cut id.orig_h id.resp_h id.resp_p service < conn.log
zeek-cut -d ts query answers < dns.log                 # -d = human-readable timestamps
zeek-cut host uri < http.log
zeek-cut server_name < ssl.log
```

## 4. Handy combinations

```sh
# top talkers (source IPs)
zeek-cut id.orig_h < conn.log | sort | uniq -c | sort -rn | head

# most queried domains
zeek-cut query < dns.log | sort | uniq -c | sort -rn | head

# connections to a given IP
zeek-cut id.orig_h id.resp_h id.resp_p < conn.log | grep 74.121.138.87

# longest connections
zeek-cut duration id.orig_h id.resp_h < conn.log | sort -rn | head
```
