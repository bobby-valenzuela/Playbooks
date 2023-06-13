# Run as root/sudo

# List partitions (3ways): 
```bash
parted -l
lsblk -e7
cat /proc/partitions
```

# Enter parted session:
```bash
parted /dev/sdb
```

# Get partition info (use throughout):
```bash
print
```

# Create partition table:
```bash
mklabel gpt
```

# Create partition:
```bash
mkpart primary ext4 0% 100%
```

# Quit parted session:
```bash
quit
```

# List partitions again: Repeat step #1
```bash
parted -l
```

# Confirm that kernel has an updated view of anything that has been changed (avoids a reboot):
```bash
partprobe
```

# Make filesystem from partition name:
```bash
mkfs -t ext4 /dev/sdb1
```

# Get parition UUID (2 ways): 
```bash
blkid
lsblk -f
```

# Add to fstab (can also use partition name):
```bash
UUID=1234 /dev/sdb1 ext4 defaults 0 0
```
