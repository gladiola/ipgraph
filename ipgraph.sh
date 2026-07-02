#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: ipgraph.sh [-o OUTPUT_DIR] LOG_FILE [LOG_FILE ...]

Reads one or more log files, extracts IPv4 addresses and URL calls,
queries Shodan CLI for each discovered IPv4, and builds graph artifacts
for visualization (DOT + Mermaid + GraphML + CSV).

Options:
  -o OUTPUT_DIR   Directory for output artifacts (default: ./output)
  -h              Show this help text

Environment:
  SHODANCLI_BIN   Explicit shodan CLI binary to use (default: auto-detect shodan/shodancli)
USAGE
}

output_dir="./output"

while getopts ":o:h" opt; do
  case "$opt" in
    o) output_dir="$OPTARG" ;;
    h)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 1
      ;;
  esac
done
shift $((OPTIND - 1))

if [ "$#" -lt 1 ]; then
  usage >&2
  exit 1
fi

mkdir -p "$output_dir"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

all_lines="$tmp_dir/all_lines.tsv"
ips_file="$tmp_dir/ips.txt"
url_rows="$tmp_dir/url_rows.tsv"

: > "$all_lines"
: > "$ips_file"
: > "$url_rows"

line_index=0
for log_file in "$@"; do
  if [ ! -f "$log_file" ]; then
    echo "Skipping missing file: $log_file" >&2
    continue
  fi

  while IFS= read -r line || [ -n "$line" ]; do
    line_index=$((line_index + 1))
    printf '%s\t%s\t%s\n' "$log_file" "$line_index" "$line" >> "$all_lines"

    while IFS= read -r ip; do
      printf '%s\n' "$ip" >> "$ips_file"
    done < <(grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' <<<"$line" | awk -F. '$1<256 && $2<256 && $3<256 && $4<256' || true)

    while IFS= read -r url; do
      printf '%s\t%s\t%s\t%s\n' "$log_file" "$line_index" "$url" "$line" >> "$url_rows"
    done < <(grep -oE "https?://[^ \"'<>)]+" <<<"$line" || true)

    while IFS= read -r url; do
      printf '%s\t%s\t%s\t%s\n' "$log_file" "$line_index" "$url" "$line" >> "$url_rows"
    done < <(grep -oE "(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) /[^ \"'<>]+" <<<"$line" | sed 's/^[A-Z]* //' || true)
  done < "$log_file"
done

if [ ! -s "$all_lines" ]; then
  echo "No readable log content found in provided files." >&2
  exit 1
fi

sort -u "$ips_file" -o "$ips_file"
sort -u "$url_rows" -o "$url_rows"

shodan_bin="${SHODANCLI_BIN:-}"
if [ -z "$shodan_bin" ]; then
  if command -v shodan >/dev/null 2>&1; then
    shodan_bin="shodan"
  elif command -v shodancli >/dev/null 2>&1; then
    shodan_bin="shodancli"
  fi
fi

ip_inventory_csv="$output_dir/ip_inventory.csv"
calls_csv="$output_dir/calls.csv"
graph_dot="$output_dir/maltego_graph.dot"
graph_mmd="$output_dir/maltego_graph.mmd"
graph_graphml="$output_dir/maltego_graph.graphml"

printf 'ip,ports,country,city,org\n' > "$ip_inventory_csv"

get_shodan_info() {
  local ip="$1"
  local json

  if [ -z "$shodan_bin" ]; then
    printf 'unknown,unknown,unknown,unknown\n'
    return 0
  fi

  if ! json="$($shodan_bin host "$ip" --format json 2>/dev/null)"; then
    printf 'unknown,unknown,unknown,unknown\n'
    return 0
  fi

  local ports country city org
  ports="$(jq -r '[.ports[]?] | map(tostring) | join(";") | if .=="" then "none" else . end' <<<"$json" 2>/dev/null || printf 'unknown')"
  country="$(jq -r '.country_name // "unknown"' <<<"$json" 2>/dev/null || printf 'unknown')"
  city="$(jq -r '.city // "unknown"' <<<"$json" 2>/dev/null || printf 'unknown')"
  org="$(jq -r '.org // "unknown"' <<<"$json" 2>/dev/null || printf 'unknown')"

  printf '%s,%s,%s,%s\n' "$ports" "$country" "$city" "$org"
}

xml_escape() {
  local value="${1-}"
  value="${value//&/&amp;}"
  value="${value//</&lt;}"
  value="${value//>/&gt;}"
  value="${value//\"/&quot;}"
  value="${value//\'/&apos;}"
  printf '%s' "$value"
}

is_valid_ipv4() {
  local ip="$1"
  local o1 o2 o3 o4

  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS='.' read -r o1 o2 o3 o4 <<<"$ip"
  [ "$o1" -le 255 ] && [ "$o2" -le 255 ] && [ "$o3" -le 255 ] && [ "$o4" -le 255 ]
}

if [ -s "$ips_file" ]; then
  while IFS= read -r ip; do
    [ -n "$ip" ] || continue
    info="$(get_shodan_info "$ip")"
    IFS=',' read -r ports country city org <<<"$info"
    printf '%s,%s,%s,%s,%s\n' "$ip" "$ports" "$country" "$city" "$org" >> "$ip_inventory_csv"
  done < "$ips_file"
fi

printf 'source,target,url,file,line\n' > "$calls_csv"

declare -A ip_meta
if [ -s "$ip_inventory_csv" ]; then
  while IFS=',' read -r ip ports country city org; do
    if [ "$ip" = "ip" ]; then
      continue
    fi
    ip_meta["$ip"]="ports=$ports\\nloc=$city, $country"
  done < "$ip_inventory_csv"
fi

build_node_label() {
  local name="$1"
  local label="$name"

  if [ -n "${ip_meta[$name]:-}" ]; then
    label+=$'\n'"${ip_meta[$name]//\\n/$'\n'}"
  fi

  printf '%s' "$label"
}

{
  printf 'digraph maltego {\n'
  printf '  rankdir=LR;\n'
  printf '  node [shape=box, style=rounded];\n'

  while IFS=$'\t' read -r file ln url line; do
    [ -n "$url" ] || continue

    src_ip="$(grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' <<<"$line" | awk -F. '$1<256 && $2<256 && $3<256 && $4<256' | head -n1 || true)"

    target="$(sed -E 's#https?://([^/]+).*#\1#' <<<"$url")"
    target_ip="$(grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' <<<"$target" | awk -F. '$1<256 && $2<256 && $3<256 && $4<256' | head -n1 || true)"

    if [ -n "$target_ip" ]; then
      target="$target_ip"
    fi

    if [ -z "$src_ip" ]; then
      src_ip="unknown_source"
    fi

    printf '%s,%s,%s,%s,%s\n' "$src_ip" "$target" "$url" "$file" "$ln" >> "$calls_csv"

    src_label="$src_ip"
    tgt_label="$target"

    if [ -n "${ip_meta[$src_ip]:-}" ]; then
      src_label="$src_ip\\n${ip_meta[$src_ip]}"
    fi
    if [ -n "${ip_meta[$target]:-}" ]; then
      tgt_label="$target\\n${ip_meta[$target]}"
    fi

    safe_url="$(sed 's/"/\\"/g' <<<"$url")"
    printf '  "%s" [label="%s"];\n' "$src_ip" "$src_label"
    printf '  "%s" [label="%s"];\n' "$target" "$tgt_label"
    printf '  "%s" -> "%s" [label="%s"];\n' "$src_ip" "$target" "$safe_url"
  done < "$url_rows"

  printf '}\n'
} > "$graph_dot"

{
  printf 'graph LR\n'
  while IFS=',' read -r source target url file line_no; do
    if [ "$source" = "source" ]; then
      continue
    fi
    s="$(sed 's/[^A-Za-z0-9_]/_/g' <<<"$source")"
    t="$(sed 's/[^A-Za-z0-9_]/_/g' <<<"$target")"
    safe_url="$(sed 's/"/\\"/g' <<<"$url")"
    printf '  %s["%s"] -->|"%s"| %s["%s"]\n' "$s" "$source" "$safe_url" "$t" "$target"
  done < "$calls_csv"
} > "$graph_mmd"

graphml_nodes="$tmp_dir/graphml_nodes.xml"
graphml_edges="$tmp_dir/graphml_edges.xml"

: > "$graphml_nodes"
: > "$graphml_edges"

declare -A graphml_node_ids
declare -A graphml_node_written
graphml_next_id=0
graphml_edge_id=0

register_graphml_node() {
  local name="$1"
  local node_id="${graphml_node_ids[$name]:-}"
  local node_type="host"
  local node_label

  if [ -z "$node_id" ]; then
    node_id="n$graphml_next_id"
    graphml_node_ids["$name"]="$node_id"
    graphml_next_id=$((graphml_next_id + 1))
  fi

  if [ -n "${graphml_node_written[$name]:-}" ]; then
    return 0
  fi

  if is_valid_ipv4 "$name"; then
    node_type="ipv4"
  elif [ "$name" = "unknown_source" ]; then
    node_type="synthetic"
  fi

  node_label="$(build_node_label "$name")"

  {
    printf '    <node id="%s">\n' "$node_id"
    printf '      <data key="label">%s</data>\n' "$(xml_escape "$node_label")"
    printf '      <data key="name">%s</data>\n' "$(xml_escape "$name")"
    printf '      <data key="type">%s</data>\n' "$(xml_escape "$node_type")"
    printf '    </node>\n'
  } >> "$graphml_nodes"

  graphml_node_written["$name"]=1
}

if [ -s "$ip_inventory_csv" ]; then
  while IFS=',' read -r ip ports country city org; do
    if [ "$ip" = "ip" ]; then
      continue
    fi
    register_graphml_node "$ip"
  done < "$ip_inventory_csv"
fi

while IFS=',' read -r source target url file line_no; do
  if [ "$source" = "source" ]; then
    continue
  fi

  register_graphml_node "$source"
  register_graphml_node "$target"

  {
    printf '    <edge id="e%s" source="%s" target="%s">\n' \
      "$graphml_edge_id" "${graphml_node_ids[$source]}" "${graphml_node_ids[$target]}"
    printf '      <data key="label">%s</data>\n' "$(xml_escape "$url")"
    printf '      <data key="url">%s</data>\n' "$(xml_escape "$url")"
    printf '      <data key="file">%s</data>\n' "$(xml_escape "$file")"
    printf '      <data key="line">%s</data>\n' "$(xml_escape "$line_no")"
    printf '    </edge>\n'
  } >> "$graphml_edges"

  graphml_edge_id=$((graphml_edge_id + 1))
done < "$calls_csv"

{
  graphml_schema_location="http://graphml.graphdrawing.org/xmlns http://graphml.graphdrawing.org/xmlns/1.0/graphml.xsd"
  printf '<?xml version="1.0" encoding="UTF-8"?>\n'
  printf '<graphml xmlns="%s" xmlns:xsi="%s" xsi:schemaLocation="%s">\n' \
    "http://graphml.graphdrawing.org/xmlns" \
    "http://www.w3.org/2001/XMLSchema-instance" \
    "$graphml_schema_location"
  printf '  <key id="label" for="all" attr.name="label" attr.type="string"/>\n'
  printf '  <key id="name" for="node" attr.name="name" attr.type="string"/>\n'
  printf '  <key id="type" for="node" attr.name="type" attr.type="string"/>\n'
  printf '  <key id="url" for="edge" attr.name="url" attr.type="string"/>\n'
  printf '  <key id="file" for="edge" attr.name="file" attr.type="string"/>\n'
  printf '  <key id="line" for="edge" attr.name="line" attr.type="string"/>\n'
  printf '  <graph id="maltego" edgedefault="directed">\n'
  cat "$graphml_nodes"
  cat "$graphml_edges"
  printf '  </graph>\n'
  printf '</graphml>\n'
} > "$graph_graphml"

printf 'Wrote:\n  %s\n  %s\n  %s\n  %s\n  %s\n' \
  "$ip_inventory_csv" "$calls_csv" "$graph_dot" "$graph_mmd" "$graph_graphml"

if [ -z "$shodan_bin" ]; then
  echo "Shodan CLI not found; geolocation/ports are marked as unknown." >&2
fi
