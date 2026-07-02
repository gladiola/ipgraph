# ipgraph

`ipgraph.sh` reads one or more log files, extracts IPv4 addresses and URL calls, enriches discovered IPv4 hosts with `shodan`/`shodancli` data (open ports + geolocation), and emits graph artifacts.

## What the script is

`ipgraph.sh` is a Bash-based investigation helper for Kali Linux. It turns raw web/server log lines into relationship data so you can see:

- which source IPs are making calls,
- which hosts are being called by URL,
- and what Shodan reports for observed IPv4 hosts (open ports + location metadata).

The generated CSV and graph files are designed for quick triage and visualization in tools like Graphviz, Mermaid, or Maltego workflows.

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
- `maltego_graph.dot` — Graphviz DOT graph
- `maltego_graph.mmd` — Mermaid graph

Render DOT with Graphviz:

```bash
dot -Tpng maltego_graph.dot -o maltego_graph.png
```

## How it works

1. Reads all provided log files line-by-line and keeps file/line provenance.
2. Extracts IPv4 candidates from each line and filters invalid octets.
3. Extracts `http://` and `https://` URLs from each line.
4. Deduplicates discovered IPs and URL rows.
5. Resolves each discovered IPv4 with Shodan CLI (`host --format json`) and records:
   - open ports,
   - country/city,
   - organization.
6. Builds `calls.csv` edges from source IP to URL target host (IP or domain).
7. Generates:
   - `maltego_graph.dot` (Graphviz directed graph with URL-labeled edges),
   - `maltego_graph.mmd` (Mermaid graph),
   - plus CSV artifacts for tabular analysis.

## Behavior notes

- If a provided file does not exist, it is skipped with a warning.
- If no readable lines are found, the script exits with an error.
- If Shodan CLI is unavailable or lookup fails, ports/location fields are written as `unknown` (graph generation still continues).
- Lines containing URLs but no source IPv4 are mapped to `unknown_source` in `calls.csv` and graphs.
