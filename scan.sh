#!/bin/bash

# Check if domains.txt exists
if [[ ! -f ./config/domains.txt ]]; then
    echo "Error: domains.txt file not found!"
    exit 1
fi

# Loop through each line in domains.txt
while IFS= read -r domain; do
    # Skip empty lines
    if [[ -z "$domain" ]]; then
        continue
    fi

    echo "Running script for domain: $domain"
    python3 scripts/run_scan.py --domain "$domain" --verbose --slack

    echo "Cleaning up scan data..."
    rm -rf ./data/content/scan*
done < ./config/domains.txt
