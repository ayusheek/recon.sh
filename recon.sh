#!/bin/bash

create_cache_dir() {
    mkdir ".cache"
}

subfinder_scan() {
    domain=$1
    output_file=$2
    subfinder -d "$domain" -o "$output_file"
}

httpx_probe() {
    hosts_file=$1
    output_file=$2
    httpx -l "$hosts_file" -o "$output_file"
}

katana_crawl() {
    live_hosts_file=$1
    output_file=$2
    scan_time=$(date +"%Y-%m-%d")

    katana -list "$live_hosts_file" -ps -o ".cache/$scan_time/passive_crawled.txt"
    katana -list "$live_hosts_file" -jc -kf -fx -xhr -aff -jsl -c 100 -o ".cache/$scan_time/active_crawled.txt"
    cat ".cache/$scan_time/passive_crawled.txt" ".cache/$scan_time/active_crawled.txt" | sort -u >> "$output_file"
}

nuclei_dast_scan() {
    nuclei -t "dast/vulnerabilities/" -l $1 -dast -c 50 -headless -sc -o $2
}

recon() {
    domain=$1
    output_dir=$2
    mkdir -p $output_dir
    subfinder_scan $domain $output_dir/"subs.txt"
    httpx_probe "subs.txt" $output_dir/"httpx.txt"
    katana_crawl $output_dir/"httpx.txt" $output_dir/"katana.txt"
    nuclei_dast_scan $output_dir/"katana.txt" $output_dir/"nuclei_dastScan_out.txt"
}
