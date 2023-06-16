Run as root/sudo

<br/>

# Viewing Disks

<br/>

List Disks (2ways): 
```bash
lsblk -e7
```
```bash
df
```

<br/>

# Creating a partition

<br/>

Enter parted session:
```bash
parted /dev/sdb
```

<br/>

Get partition info (use throughout):
```bash
print
```

<br/>

Create partition table:
```bash
mklabel gpt
```

<br/>

Create partition:
```bash
mkpart primary ext4 0% 100%
```

<br/>

Quit parted session:
```bash
quit
```

<br/>

List partitions (3ways): 
```bash 
parted -l 
```
```bash
lsblk -e7
```
```bash
lsblk -f
```
```bash
cat /proc/partitions
```

<br/>

# Creating Filesystem and Mounting

<br/>

Confirm that kernel has an updated view of anything that has been changed (avoids a reboot):
```bash
partprobe
```

<br/>

Make filesystem from partition name:
```bash
mkfs -t ext4 /dev/sdb1
```

<br/>

[Optional] Add filesystem label:
```bash
# EXT Filesystems
e2label <partition> <new name>
e2label /dev/sdb1 opt

# XFS Filesystems
xfs admin -L <new name> <partition>
xfs admin -L opt /dev/sdb1
```

Get parition UUID (2 ways): 
```bash
blkid
```
```bash
lsblk -f
```

<br/>

Add to fstab (can also use partition name):
```bash
UUID=1234 /dev/sdb1 ext4 defaults 0 0
```

Mount based on fstab:
```bash
mount -a
```

<br />

# Verifying Changes

<br/>

Verifying mount status:
```bash
# Could also use /etc/mtab, but /proc/mounts is more up to date
cat /proc/mounts
```

<br />

Viewing Partition/Filestem info/mount info:
```bash
cat /proc/partitions
```
```bash
df -h
```
```bash
lsblk -f
```
