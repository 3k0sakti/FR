# Lab 1.1: Physical Disk Imaging

## Objective
Learn to create bit-for-bit physical copies of storage devices for forensic analysis.

## Prerequisites
- Root/Administrator access
- Target storage device (USB drive for practice)
- Sufficient storage space for image

## Tools Required
- `dc3dd` or `dd`
- `ddrescue` (for damaged drives)
- `hashdeep` or `md5sum`

## Lab Exercise

### Step 1: Identify Target Device
```bash
# List all storage devices
sudo fdisk -l

# Show device information
sudo lsblk

# Get detailed device info
sudo hdparm -I /dev/sdX
```

### Step 2: Create Forensic Image
```bash
# Using our disk imaging script
sudo python3 ../../scripts/disk_image.py \
    --source /dev/sdX \
    --output evidence/practice_disk.dd \
    --hash md5 \
    --verify

# Alternative: Using dc3dd directly
sudo dc3dd if=/dev/sdX of=evidence/practice_disk.dd hash=md5 log=imaging.log

# For damaged drives: Using ddrescue
sudo ddrescue /dev/sdX evidence/practice_disk.dd evidence/practice_disk.mapfile
```

### Step 3: Verify Image Integrity
```bash
# Verify with our verification script
python3 ../../scripts/verify_acquisition.py --file evidence/practice_disk.dd

# Manual verification
md5sum evidence/practice_disk.dd
cat evidence/practice_disk.dd.md5
```

### Step 4: Analyze Image
```bash
# View partition table
fdisk -l evidence/practice_disk.dd

# Mount image (read-only)
sudo mkdir /mnt/forensic_image
sudo mount -o ro,loop evidence/practice_disk.dd /mnt/forensic_image

# Explore filesystem
ls -la /mnt/forensic_image

# Unmount when done
sudo umount /mnt/forensic_image
```

## Questions
1. Why is it important to use write-blocking when imaging drives?
2. What is the difference between physical and logical imaging?
3. How do you handle bad sectors during imaging?

## Deliverables
- Disk image file (practice_disk.dd)
- Hash verification file
- Imaging log file
- Lab report documenting process and findings

## Safety Notes
- Never image production systems without proper authorization
- Always use write-blocking hardware when possible
- Verify image integrity before analysis
- Maintain chain of custody documentation
