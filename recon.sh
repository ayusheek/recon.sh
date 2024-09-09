#!/bin/bash

subfinder_scan() {
    local domain=$1
    local output_file=$2
    subfinder -d "$domain" -o "$output_file" -all
}

httpx_probe() {
    local hosts_file=$1
    local output_file=$2
    httpx -l "$hosts_file" -o "$output_file"
}

katana_crawl() {
    local live_hosts_file=$1
    local output_file=$2
    scan_time=$(date +"%Y-%m-%d-%H-%m-%S")

    mkdir -p ".cache/$scan_time"

    katana -list "$live_hosts_file" -ps -o ".cache/$scan_time/passive_crawled.txt"
    katana -list "$live_hosts_file" -d 10 -jc -kf -fx -xhr -aff -jsl -c 100 -o ".cache/$scan_time/active_crawled.txt"
    cat ".cache/$scan_time/passive_crawled.txt" ".cache/$scan_time/active_crawled.txt" | sort -u >> "$output_file"
}

nuclei_dast_scan() {
    local urls_file=$1
    local output_file=$2
    nuclei -t "dast/vulnerabilities/" -l "$urls_file" -dast -c 50 -headless -sc -o "$output_file"
}

recon() {
    local domain=$1
    local output_dir=$2
    mkdir -p $output_dir
    subfinder_scan $domain $output_dir/"subs.txt"
    httpx_probe $output_dir/"subs.txt" $output_dir/"httpx.txt"
    katana_crawl $output_dir/"httpx.txt" $output_dir/"katana.txt"
    nuclei_dast_scan $output_dir/"katana.txt" $output_dir/"nuclei_dastScan_out.txt"
}

set -e

if [[ $# -ne 2 ]]; then
    echo -e "\nUsage: $0 <domain> <ouptut_dir>\n"
    echo "Example:"
    echo -e "  ./recon.sh example.com example\n"
    exit 0
fi

# Usage: recon.sh <domain> <output_dir>

set -e  # exit on any error
recon "$1" "$2"
