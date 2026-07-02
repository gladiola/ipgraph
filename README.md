# ipgraph

`ipgraph.sh` reads one or more log files, extracts IPv4 addresses and URL calls, enriches discovered IPv4 hosts with `shodan`/`shodancli` data (open ports + geolocation), and emits graph artifacts.

## Requirements (Kali Linux)

- Bash 4+
- `grep`, `awk`, `sed`, `sort`
- `jq`
- `shodan` (or `shodancli`) authenticated with your API key for host lookups

## Usage

```bash
./ipgraph.sh /var/log/apache2/access.log
./ipgraph.sh -o ./out /var/log/nginx/access.log /var/log/nginx/error.log
```

## Output

The output directory contains:

- `ip_inventory.csv` — discovered IPv4s + Shodan open ports/geolocation/org
- `calls.csv` — source/target/url/file/line relationships from log lines
- `matego_graph.dot` — Graphviz DOT graph
- `matego_graph.mmd` — Mermaid graph

Render DOT with Graphviz:

```bash
dot -Tpng matego_graph.dot -o matego_graph.png
```
