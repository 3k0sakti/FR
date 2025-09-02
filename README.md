# Digital Forensics Data Acquisition Lab
*Hands-on laboratory for digital forensic data acquisition: disk, RAM, and network*


## 📋 Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Lab Modules](#lab-modules)
- [Quick Start](#quick-start)
- [Data Acquisition Workflows](#data-acquisition-workflows)
- [Contributing](#contributing)
- [License](#license)

## 🔍 Overview

This repository focuses on **data acquisition techniques** for digital forensic investigations. The labs provide hands-on training for acquiring data from both live and dead systems, covering three critical data sources: **disk storage**, **RAM memory**, and **network traffic**.

### Core Data Acquisition Areas

- **Disk Data Acquisition**: Physical and logical disk imaging, storage device cloning
- **RAM Memory Acquisition**: Live memory dumps, volatile data preservation  
- **Network Data Acquisition**: Traffic capture, packet analysis, communication data collection

## 🛠 Prerequisites

### Hardware Requirements
- Computer with minimum 8GB RAM (16GB recommended for memory acquisition)
- Multiple storage devices for imaging practice (USB drives, external HDDs)
- Network adapter for packet capture exercises

### Software Requirements
- **Operating System**: Ubuntu 22.04 LTS, Kali Linux, or similar Linux distribution
- **Virtualization**: VMware Workstation/VirtualBox for isolated environments
- **Python**: 3.8+ with pip for acquisition scripts

This repository focuses exclusively on **data acquisition techniques** for digital forensic investigations. The labs provide hands-on training for acquiring data from both live (running) and dead (offline) systems, covering the four critical data sources: **disk storage**, **RAM memory**, **network traffic**, and **cache data**.

### Core Data Acquisition Areas

- **Live Data Acquisition**: Real-time memory dumps, active network connections, volatile system state
- **Dead Data Acquisition**: Disk imaging, storage device cloning, offline data extraction  
- **RAM Memory Acquisition**: System memory capture, memory dump analysis, volatile data preservation
- **Network Data Acquisition**: Traffic capture, packet analysis, network artifact collection
- **Cache Data Acquisition**: Browser cache, application cache, system cache extraction

## Prerequisites

### Hardware Requirements
- Computer with minimum 8GB RAM (16GB recommended)
- USB drive 32GB+ for evidence storage
- Network adapter for packet capture
- Virtual machine setup for isolated testing

### Software Requirements
- **Operating System**: Ubuntu 22.04 LTS, Kali Linux, or similar
- **Virtualization**: VMware Workstation/VirtualBox
- **Python**: 3.8+ with pip

## Installation

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/digital-forensics-lab.git
cd digital-forensics-lab
```

### 2. Run Setup Script
```bash
chmod +x setup.sh
./setup.sh
```

### 3. Manual Installation (if needed)
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install disk imaging tools
sudo apt install -y dc3dd ddrescue sleuthkit

# Install memory acquisition tools  
sudo apt install -y volatility3 lime-forensics-dkms

# Install network capture tools
sudo apt install -y wireshark tcpdump nmap

# Install verification and hashing tools
sudo apt install -y hashdeep md5deep sha256sum

# Install Python dependencies
pip3 install -r requirements.txt

# Download LiME (Linux Memory Extractor)
wget -O /tmp/lime.tar.gz https://github.com/504ensicsLabs/LiME/archive/master.tar.gz
tar -xzf /tmp/lime.tar.gz -C tools/
```

## Quick Start

### RAM Memory Acquisition
```bash
# Capture live system memory
sudo python3 scripts/memory_acquire.py --output evidence/memory_dump.raw --format lime

# Verify memory dump integrity
python3 scripts/verify_memory.py --dump evidence/memory_dump.raw
```

### Disk Data Acquisition
```bash
# Create bit-for-bit disk image
sudo python3 scripts/disk_image.py --source /dev/sdb --output evidence/disk.dd --verify

# Create compressed disk image
sudo python3 scripts/disk_image.py --source /dev/sdb --output evidence/disk.E01 --format ewf
```

### Network Data Acquisition
```bash
# Capture network traffic for 5 minutes
sudo python3 scripts/network_capture.py --interface eth0 --duration 300 --output evidence/

# Capture specific network protocol
sudo python3 scripts/network_capture.py --interface eth0 --filter "port 80" --output evidence/
```

## Lab Modules

### Module 1: Disk Data Acquisition
Master techniques for acquiring data from storage devices and file systems.

- **Lab 1.1**: [Physical Disk Imaging](labs/01-disk-acquisition/physical-imaging.md)
- **Lab 1.2**: [Logical Volume Acquisition](labs/01-disk-acquisition/logical-acquisition.md)
- **Lab 1.3**: [Encrypted Storage Acquisition](labs/01-disk-acquisition/encrypted-acquisition.md)
- **Lab 1.4**: [Live Disk Imaging](labs/01-disk-acquisition/live-imaging.md)

### Module 2: RAM Memory Acquisition
Specialized focus on memory acquisition techniques and tools.

- **Lab 2.1**: [Windows Memory Acquisition](labs/02-memory-acquisition/windows-memory.md)
- **Lab 2.2**: [Linux Memory Acquisition](labs/02-memory-acquisition/linux-memory.md)
- **Lab 2.3**: [Virtual Machine Memory Acquisition](labs/02-memory-acquisition/vm-memory.md)
- **Lab 2.4**: [Memory Acquisition Verification](labs/02-memory-acquisition/memory-verification.md)

### Module 3: Network Data Acquisition
Comprehensive network traffic and communication data capture techniques.

- **Lab 3.1**: [Packet Capture Fundamentals](labs/03-network-acquisition/packet-capture.md)
- **Lab 3.2**: [Protocol-Specific Acquisition](labs/03-network-acquisition/protocol-acquisition.md)
- **Lab 3.3**: [Wireless Network Acquisition](labs/03-network-acquisition/wireless-acquisition.md)
- **Lab 3.4**: [Network Device Configuration Acquisition](labs/03-network-acquisition/device-config.md)

## 🔧 Data Acquisition Tools and Scripts

### Core Acquisition Scripts
```
scripts/
├── memory_acquire.py      # RAM memory acquisition
├── disk_image.py         # Disk and storage imaging
├── network_capture.py    # Network traffic capture
├── verify_acquisition.py # Acquisition integrity verification
└── chain_custody.py      # Chain of custody documentation
```

### Specialized Tools
```
tools/
├── lime/                 # Linux Memory Extractor
├── dc3dd/               # Enhanced dd for forensics
├── wireshark/           # Network protocol analyzer
└── tcpdump/             # Command-line packet analyzer
```

## Example Workflows

## 📊 Data Acquisition Workflows

### Complete System Acquisition
```bash
# 1. Create case directory
mkdir -p evidence/CASE-2024-001

# 2. RAM memory acquisition
sudo scripts/memory_acquire.py --output evidence/CASE-2024-001/memory.raw --format lime

# 3. Disk imaging
sudo scripts/disk_image.py --source /dev/sdb --output evidence/CASE-2024-001/disk.dd --verify

# 4. Network capture (if system is live)
sudo scripts/network_capture.py --interface eth0 --duration 300 --output evidence/CASE-2024-001/

# 5. Verify all acquisitions
python3 scripts/verify_acquisition.py --case evidence/CASE-2024-001/
```

### Live System Triage
```bash
# 1. Quick memory snapshot
sudo scripts/memory_acquire.py --output evidence/triage_memory.raw --quick

# 2. Active network connections
sudo scripts/network_capture.py --interface eth0 --duration 60 --filter "established"

# 3. System disk snapshot
sudo scripts/disk_image.py --source /dev/sda1 --output evidence/triage_disk.dd --quick
```

### Data Breach Investigation
```bash
# 1. Create case directory
mkdir -p evidence/DB-2024-002

# 2. Disk imaging
sudo scripts/disk_image.py --source /dev/sdb --output evidence/DB-2024-002/server_disk.dd --hash

# 3. File recovery
python3 scripts/file_carve.py --image evidence/DB-2024-002/server_disk.dd --output evidence/DB-2024-002/recovered/

# 4. Generate report
python3 automation/report_generator.py --case DB-2024-002 --template breach_investigation
```

##  Documentation Structure

## 📝 Documentation Structure

```
docs/
├── getting-started.md
├── acquisition-guide.md
├── tool-reference.md
├── best-practices.md
└── legal-considerations.md

labs/
├── 01-disk-acquisition/
├── 02-memory-acquisition/
└── 03-network-acquisition/

examples/
├── complete-acquisition/
├── live-triage/
├── disk-imaging/
└── network-capture/
```

##  Legal and Ethical Guidelines

### Important Notes
-  **Authorization Required**: Only perform these techniques on systems you own or have explicit written permission to investigate
-  **Evidence Integrity**: Always maintain proper chain of custody
-  **Documentation**: Document all procedures for potential legal proceedings
-  **Compliance**: Ensure compliance with local laws and regulations

### Chain of Custody Template
```bash
# Generate chain of custody documentation
python3 scripts/chain_custody.py --case CASE-2024-001 --investigator "John Doe" --evidence evidence/
```


