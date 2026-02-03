#!/bin/bash

# Backup the file first
cp ~/.local/lib/wireshark/plugins/ask.lua ~/.local/lib/wireshark/plugins/ask.lua.backup

# Update all show_result_window calls to show_result_window_with_buttons
# Format: show_result_window_with_buttons(title, content, query_type, query_target)

sed -i '' \
-e 's/show_result_window("IP Registration Info (RDAP): " \.\. ip, formatted)/show_result_window_with_buttons("IP Registration Info (RDAP): " .. ip, formatted, "IP RDAP", ip)/g' \
-e 's/show_result_window("IP Reputation: " \.\. ip, formatted)/show_result_window_with_buttons("IP Reputation: " .. ip, formatted, "AbuseIPDB", ip)/g' \
-e 's/show_result_window("URL Reputation: " \.\. url, formatted)/show_result_window_with_buttons("URL Reputation: " .. url, formatted, "urlscan.io", url)/g' \
-e 's/show_result_window("VirusTotal IP: " \.\. ip, formatted)/show_result_window_with_buttons("VirusTotal IP: " .. ip, formatted, "VirusTotal IP", ip)/g' \
-e 's/show_result_window("VirusTotal Domain: " \.\. domain, formatted)/show_result_window_with_buttons("VirusTotal Domain: " .. domain, formatted, "VirusTotal Domain", domain)/g' \
-e 's/show_result_window("VirusTotal URL: " \.\. url, formatted)/show_result_window_with_buttons("VirusTotal URL: " .. url, formatted, "VirusTotal URL", url)/g' \
-e 's/show_result_window("Shodan IP: " \.\. ip, formatted)/show_result_window_with_buttons("Shodan IP: " .. ip, formatted, "Shodan", ip)/g' \
-e 's/show_result_window("IPinfo IP Intelligence: " \.\. ip, formatted)/show_result_window_with_buttons("IPinfo IP Intelligence: " .. ip, formatted, "IPinfo", ip)/g' \
~/.local/lib/wireshark/plugins/ask.lua

echo "Updated callback functions"
