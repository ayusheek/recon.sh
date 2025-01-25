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

httpx_filter_dupe() {
    local hosts_file=$1
    local output_file="$2"
    httpx -l -fd "$hosts_file" -o "$output_file"
}

subdomain_takeover_scan() {
    local live_hosts_file=$1
    local output_file=$2
    nuclei -t "http/takeovers/" -l "$live_hosts_file" -o "$output_file"
}

katana_crawl() {
    local filtered_live_hosts_file=$1
    local output_file=$2
    local depth_to_crawl=$3
    local max_duration_to_crawl=$4
    scan_time=$(date +"%Y-%m-%d-%H-%m-%S")

    mkdir -p ".cache/$scan_time"

    katana -list "$filtered_live_hosts_file" -ps -o ".cache/$scan_time/passive_crawled.txt"
    katana -list "$filtered_live_hosts_file" -d "$depth_to_crawl" -jc -kf -fx -xhr -aff -jsl -c 100 \
                -o ".cache/$scan_time/active_crawled.txt" -ct "$max_duration_to_crawl"
    
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
    httpx_probe $output_dir/"subs.txt" $output_dir/"livehosts.txt"
    httpx_filter_dupe $output_dir/"livehosts.txt" $output_dir/"filtered_livehosts.txt"
    subdomain_takeover_scan $output_dir/"livehosts.txt" $output_dir/"subdomain_takeover_scan.txt"
    katana_crawl $output_dir/"filtered_livehosts.txt" $output_dir/"crawled.txt" 6 15m # depth and max duration to crawl
    nuclei_dast_scan $output_dir/"crawled.txt" $output_dir/"nuclei_dastscan_out.txt"
}

if [[ $# -ne 2 ]]; then
    echo -e "\nUsage: $0 <domain> <ouptut_dir>\n"
    echo "Example:"
    echo -e "  ./recon.sh example.com example\n"
    exit 0
fi

set -e  # exit on any error

# Usage: recon.sh <domain> <output_dir>
recon "$1" "$2"
