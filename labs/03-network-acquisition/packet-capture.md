# Lab 3.1: Packet Capture Fundamentals

## Objective
Learn to capture and analyze network traffic for forensic investigations.

## Prerequisites
- Network interface access
- Root/Administrator privileges
- Active network traffic (or traffic generator)

## Tools Required
- `tcpdump`
- `wireshark/tshark`
- `network_capture.py` script

## Lab Exercise

### Step 1: Network Interface Discovery
```bash
# List network interfaces
ip link show
ifconfig -a

# Check interface status
ip addr show
iwconfig  # For wireless interfaces

# Monitor interface statistics
ip -s link show eth0
```

### Step 2: Basic Packet Capture
```bash
# Using our network capture script
sudo python3 ../../scripts/network_capture.py \
    --interface eth0 \
    --duration 300 \
    --output evidence/

# Using tcpdump directly
sudo tcpdump -i eth0 -w evidence/basic_capture.pcap

# Capture specific protocols
sudo tcpdump -i eth0 port 80 -w evidence/http_traffic.pcap
sudo tcpdump -i eth0 port 22 -w evidence/ssh_traffic.pcap
```

### Step 3: Advanced Capture Filters
```bash
# HTTP traffic only
sudo tcpdump -i eth0 'tcp port 80' -w evidence/http_only.pcap

# Traffic to/from specific host
sudo tcpdump -i eth0 'host 192.168.1.100' -w evidence/host_specific.pcap

# DNS queries
sudo tcpdump -i eth0 'port 53' -w evidence/dns_queries.pcap

# HTTPS traffic
sudo tcpdump -i eth0 'tcp port 443' -w evidence/https_traffic.pcap
```

### Step 4: Traffic Analysis
```bash
# Basic packet count
tcpdump -r evidence/basic_capture.pcap -n | wc -l

# Protocol distribution
tcpdump -r evidence/basic_capture.pcap -n | \
    awk '{print $3}' | sort | uniq -c | sort -nr

# Top talkers
tcpdump -r evidence/basic_capture.pcap -n | \
    awk '{print $3 " -> " $5}' | sort | uniq -c | sort -nr | head -10

# Using tshark for detailed analysis
tshark -r evidence/basic_capture.pcap -T fields -e ip.src -e ip.dst -e tcp.port | head -20
```

### Step 5: Protocol-Specific Analysis
```bash
# HTTP requests
tshark -r evidence/http_traffic.pcap -T fields \
    -e http.request.method -e http.request.uri -e http.host

# DNS queries
tshark -r evidence/dns_queries.pcap -T fields \
    -e dns.qry.name -e dns.resp.addr

# Extract files from HTTP traffic
tshark -r evidence/http_traffic.pcap --export-objects http,extracted_files/
```

## Traffic Analysis Checklist
- [ ] Total packet count
- [ ] Protocol distribution
- [ ] Top source/destination IPs
- [ ] Suspicious ports or protocols
- [ ] Unusual traffic patterns
- [ ] Clear-text credentials
- [ ] File transfers
- [ ] Malicious domains/IPs

## Common Network Artifacts
- Web browsing history
- Email communications
- File transfers
- Remote access sessions
- Malware communications
- Clear-text passwords
- DNS lookups

## Questions
1. What protocols are most commonly used in your capture?
2. Can you identify any suspicious network activity?
3. What information can be extracted from DNS queries?
4. How can you detect potential data exfiltration?

## Deliverables
- Packet capture files (.pcap)
- Traffic analysis report
- Protocol statistics
- Identified security concerns

## Legal Considerations
- Only capture traffic on networks you own or have permission to monitor
- Be aware of privacy laws in your jurisdiction
- Properly secure captured data
- Maintain chain of custody
