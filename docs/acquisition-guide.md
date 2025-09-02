# Digital Forensics Acquisition Guide

## Overview
This guide covers best practices for digital evidence acquisition using the tools in this lab.

## General Principles

### 1. Legal Requirements
- Obtain proper authorization before acquisition
- Follow local laws and regulations
- Maintain chain of custody documentation
- Use forensically sound procedures

### 2. Technical Requirements
- Write-protect source media when possible
- Create bit-for-bit copies
- Generate cryptographic hashes
- Document all actions and findings

### 3. Documentation Requirements
- Record acquisition parameters
- Document system configuration
- Note any anomalies or errors
- Maintain detailed logs

## Acquisition Types

### Disk Acquisition

#### Best Practices
- Use hardware write blockers when available
- Verify source media is healthy
- Choose appropriate imaging tool based on situation
- Always verify image integrity

#### Common Scenarios
- **Live System**: Use `dd` with care, consider memory acquisition first
- **Powered Off**: Remove drive, use hardware write blocker
- **Damaged Media**: Use `ddrescue` for recovery attempts
- **Large Drives**: Use compression and splitting options

#### Tool Selection
- **dd**: Fast, basic imaging
- **dc3dd**: Enhanced features, better logging
- **ddrescue**: Best for damaged media

### Memory Acquisition

#### Best Practices
- Acquire memory before disk when system is live
- Use appropriate tool for target OS
- Minimize system interaction during acquisition
- Document running processes and network connections

#### Common Scenarios
- **Windows**: Use LiME kernel module or specialized tools
- **Linux**: Use LiME or /dev/mem approaches
- **Virtual Machines**: Snapshot memory through hypervisor
- **Mobile Devices**: Requires specialized tools and methods

#### Tool Selection
- **LiME**: Cross-platform kernel module
- **dd**: Direct memory access (limited)
- **Volatility**: Analysis tool with acquisition capabilities

### Network Acquisition

#### Best Practices
- Position capture point strategically
- Use appropriate capture filters
- Ensure sufficient storage space
- Monitor capture performance

#### Common Scenarios
- **Live Investigation**: Real-time monitoring
- **Incident Response**: Targeted capture
- **Forensic Analysis**: Full packet capture
- **Network Troubleshooting**: Filtered capture

#### Tool Selection
- **tcpdump**: Command-line packet capture
- **Wireshark/tshark**: GUI and CLI analysis
- **nmap**: Network scanning and discovery

## Quality Assurance

### Verification Steps
1. **Hash Verification**: Compare source and image hashes
2. **Metadata Review**: Check acquisition logs and metadata
3. **File System Check**: Verify file system integrity
4. **Sample Comparison**: Compare random sectors/files

### Common Issues
- **Hash Mismatches**: Check for write-blocking, cable issues
- **Incomplete Images**: Verify available space, check for errors
- **Permission Errors**: Ensure proper privileges, check file permissions
- **Performance Issues**: Adjust buffer sizes, check hardware

## Workflow Examples

### Complete Disk Acquisition Workflow
1. Document system state
2. Apply write blocker
3. Create working directory
4. Start acquisition with verification
5. Document completion
6. Store evidence securely

### Memory Acquisition Workflow
1. Minimize system interaction
2. Document running processes
3. Load acquisition tool
4. Capture memory image
5. Verify image integrity
6. Document acquisition parameters

### Network Acquisition Workflow
1. Identify capture points
2. Configure capture parameters
3. Start background capture
4. Monitor capture progress
5. Stop and verify capture
6. Analyze captured data

## Troubleshooting

### Common Disk Issues
- **Device busy**: Stop services, unmount filesystems
- **Permission denied**: Use sudo, check device permissions
- **I/O errors**: Check cables, try different interface
- **Slow imaging**: Adjust block size, check hardware

### Common Memory Issues
- **Module load failure**: Check kernel compatibility
- **Insufficient space**: Clear disk space, use compression
- **System crash**: Minimize system load during acquisition
- **Access denied**: Ensure root privileges

### Common Network Issues
- **No packets captured**: Check interface, permissions
- **High packet loss**: Reduce capture rate, increase buffers
- **Storage full**: Monitor space, implement rotation
- **Permission errors**: Check interface access rights

## Legal and Ethical Considerations

### Authorization
- Always obtain proper legal authority
- Document authorization clearly
- Respect privacy boundaries
- Follow organizational policies

### Chain of Custody
- Document every transfer
- Maintain secure storage
- Log all access attempts
- Preserve original evidence

### Reporting
- Document methodology
- Include technical details
- Note any limitations
- Provide clear conclusions
