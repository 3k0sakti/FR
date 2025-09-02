# Lab 2.1: Windows Memory Acquisition

## Objective
Learn to acquire volatile memory from Windows systems for forensic analysis.

## Prerequisites
- Windows system (VM recommended)
- Administrative privileges
- Memory acquisition tools

## Tools Required
- `memory_acquire.py` script
- LiME (for Linux VMs)
- Windows memory acquisition tools (WinPmem, Dumpit)

## Lab Exercise

### Step 1: Prepare System
```bash
# Check available memory
free -h  # Linux
wmic OS get TotalVisibleMemorySize  # Windows

# Check running processes
ps aux  # Linux
tasklist  # Windows
```

### Step 2: Acquire Memory
```bash
# Using our memory acquisition script (Linux)
sudo python3 ../../scripts/memory_acquire.py \
    --output evidence/windows_memory.raw \
    --format lime \
    --hash sha256 \
    --verify

# Alternative: Direct LiME usage
sudo insmod lime.ko "path=evidence/memory.lime format=lime"

# For Windows (using WinPmem)
winpmem.exe evidence/windows_memory.raw
```

### Step 3: Verify Memory Dump
```bash
# Verify acquisition
python3 ../../scripts/verify_acquisition.py --file evidence/windows_memory.raw

# Check file size (should match system RAM)
ls -lh evidence/windows_memory.raw

# Basic file analysis
file evidence/windows_memory.raw
hexdump -C evidence/windows_memory.raw | head
```

### Step 4: Basic Memory Analysis
```bash
# Using Volatility (if available)
volatility3 -f evidence/windows_memory.raw windows.info
volatility3 -f evidence/windows_memory.raw windows.pslist
volatility3 -f evidence/windows_memory.raw windows.pstree
volatility3 -f evidence/windows_memory.raw windows.netstat

# Search for strings
strings evidence/windows_memory.raw | grep -i password | head -10
```

## Common Memory Artifacts
- Running processes and threads
- Network connections
- Loaded DLLs and drivers
- Registry keys
- Command history
- Cached passwords
- Encryption keys

## Analysis Questions
1. What processes were running at the time of acquisition?
2. What network connections were active?
3. What evidence of user activity can you find?
4. Are there any suspicious processes or network connections?

## Deliverables
- Memory dump file
- Hash verification
- Volatility analysis output
- Lab report with findings

## Best Practices
- Acquire memory as soon as possible
- Minimize system interaction before acquisition
- Use hardware write-blockers when possible
- Document system state before acquisition
- Verify dump integrity immediately
