#!/usr/bin/env python3
"""Generate test .nessus files with realistic structure for merger testing."""
import os
import sys

TEMPLATE_HEADER = """<?xml version="1.0" encoding="UTF-8"?>
<NessusClientData_v2>
<Policy>
  <policyName>Test Policy</policyName>
  <Preferences>
    <ServerPreferences>
      <preference><name>max_hosts</name><value>30</value></preference>
    </ServerPreferences>
  </Preferences>
</Policy>
<Report name="Test Scan {file_num}" xmlns:cm="http://www.nessus.org/cm">
"""

TEMPLATE_HOST = """<ReportHost name="{ip}">
  <HostProperties>
    <tag name="host-ip">{ip}</tag>
    <tag name="HOST_START">Mon Jan  1 00:00:00 2024</tag>
    <tag name="HOST_END">Mon Jan  1 01:00:00 2024</tag>
    <tag name="operating-system">Linux Kernel 5.15</tag>
  </HostProperties>
  <ReportItem port="0" svc_name="general" protocol="tcp" severity="0" pluginID="19506" pluginName="Nessus Scan Information" pluginFamily="Settings">
    <description>Information about this scan.</description>
    <plugin_output>Nessus version : 10.5.0</plugin_output>
  </ReportItem>
  <ReportItem port="22" svc_name="ssh" protocol="tcp" severity="2" pluginID="10881" pluginName="SSH Protocol Versions Supported" pluginFamily="General">
    <description>SSH protocol version 2 is supported.</description>
    <solution>n/a</solution>
    <risk_factor>Medium</risk_factor>
  </ReportItem>
  <ReportItem port="443" svc_name="www" protocol="tcp" severity="1" pluginID="10863" pluginName="SSL Certificate Information" pluginFamily="General">
    <description>SSL certificate details.</description>
    <solution>n/a</solution>
    <risk_factor>Low</risk_factor>
  </ReportItem>
</ReportHost>
"""

TEMPLATE_FOOTER = """</Report>
</NessusClientData_v2>
"""

def generate_file(output_dir, file_num, start_host, num_hosts):
    filename = os.path.join(output_dir, f"scan_{file_num:03d}.nessus")
    with open(filename, "w") as f:
        f.write(TEMPLATE_HEADER.format(file_num=file_num))
        for i in range(num_hosts):
            host_num = start_host + i
            # Generate IPs across multiple subnets
            octet3 = (host_num // 254) + 1
            octet4 = (host_num % 254) + 1
            ip = f"10.0.{octet3}.{octet4}"
            f.write(TEMPLATE_HOST.format(ip=ip))
        f.write(TEMPLATE_FOOTER)
    return filename, num_hosts

def main():
    output_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    mode = sys.argv[2] if len(sys.argv) > 2 else "small"

    if mode == "small":
        # 3 files, 5 hosts each = 15 total (quick sanity check)
        configs = [(1, 0, 5), (2, 5, 5), (3, 10, 5)]
    elif mode == "medium":
        # 5 files, 100 hosts each = 500 total
        configs = [(i, (i-1)*100, 100) for i in range(1, 6)]
    elif mode == "large":
        # 10 files, 150 hosts each = 1500 total (tests 1000+ host target)
        configs = [(i, (i-1)*150, 150) for i in range(1, 11)]
    elif mode == "dedup":
        # 2 files with 3 overlapping hosts out of 5
        configs = [(1, 0, 5), (2, 3, 5)]  # hosts 3,4,5 overlap
    else:
        print(f"Unknown mode: {mode}")
        sys.exit(1)

    total = 0
    for file_num, start, count in configs:
        fname, n = generate_file(output_dir, file_num, start, count)
        total += n
        print(f"  Created {os.path.basename(fname)} with {n} hosts")

    print(f"  Total: {total} hosts across {len(configs)} files")

if __name__ == "__main__":
    main()
