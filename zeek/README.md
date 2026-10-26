# Zeek exercises

Zeek runs inside Docker; this folder is mounted at `/work` in the container.

```sh
docker compose up -d --build        # build image + start container (first time ~ few min)
docker compose exec zeek bash       # open a shell inside it
zeek -r trace.pcap                  # example: analyse a pcap -> *.log files appear here
```

Stop: `docker compose stop` · Remove everything (container + image):

```sh
docker compose down --rmi all
```
