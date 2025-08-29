#!/usr/bin/env python3
import json
from collections import Counter

import sys
logfile = sys.argv[1] if len(sys.argv) > 1 else "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"

ips = Counter()
passwords = Counter()

with open(logfile) as f:
    for line in f:
        try:
            ev = json.loads(line)
        except:
            continue
        if ev.get("eventid") in ["cowrie.login.failed", "cowrie.login.success"]:
            ips[ev["src_ip"]] += 1
            passwords[ev["password"]] += 1

print("\n🌍 Top 5 Attacker IPs:")
for ip, count in ips.most_common(5):
    print(f"{ip}: {count} attempts")

print("\n🔑 Top 5 Passwords:")
for pw, count in passwords.most_common(5):
    print(f"{pw}: {count} attempts")
