# Getting Started with Digital Forensics Lab

## Quick Setup

### 1. Run Setup Script
```bash
chmod +x setup.sh
./setup.sh
```

### 2. Test Installation
```bash
# Test memory acquisition
sudo python3 scripts/memory_acquire.py --help

# Test disk imaging
sudo python3 scripts/disk_image.py --help

# Test network capture
sudo python3 scripts/network_capture.py --help
```

## Basic Usage Examples

### Memory Acquisition
```bash
# Acquire system memory
sudo python3 scripts/memory_acquire.py \
    --output evidence/memory_dump.raw \
    --format lime \
    --verify \
    --hash sha256
```

### Disk Imaging
```bash
# Create disk image of USB drive
sudo python3 scripts/disk_image.py \
    --source /dev/sdb \
    --output evidence/usb_disk.dd \
    --verify \
    --hash md5
```

### Network Capture
```bash
# Capture network traffic for 5 minutes
sudo python3 scripts/network_capture.py \
    --interface eth0 \
    --duration 300 \
    --output evidence/
```

### Verification
```bash
# Verify single file
python3 scripts/verify_acquisition.py \
    --file evidence/disk.dd \
    --hash md5

# Verify entire case
python3 scripts/verify_acquisition.py \
    --case evidence/CASE-2024-001/ \
    --report
```

### Chain of Custody
```bash
# Create new case
python3 scripts/chain_custody.py \
    --case CASE-2024-001 \
    --investigator "Your Name" \
    --evidence evidence/

# Add custody entry
python3 scripts/chain_custody.py \
    --load-case CASE-2024-001.custody.json \
    --add-entry \
    --action "Analysis started" \
    --person "Analyst Name"
```

## Directory Structure
```
FR/
├── scripts/           # Main tools
├── labs/             # Lab exercises
├── evidence/         # Evidence storage
├── config/           # Configuration files
├── docs/            # Documentation
└── requirements.txt  # Python dependencies
```

## Next Steps
1. Review the lab exercises in `labs/`
2. Practice with the provided tools
3. Follow legal and ethical guidelines
4. Maintain proper documentation
