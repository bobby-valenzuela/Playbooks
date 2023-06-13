Run as root/sudo

<br/>

# Viewing Usage

<br/>

Get usage of root dir (1 level deep): 
```bash
du -chd / 2>/dev/null | sort -rhk 1 | head -5
```

Install/use ncdu:
```bash
apt install ncdu -y
```
```bash
ncdu ~
```

<br/>

# Clearing Space

<br />

View, archive, and vaccuum journal logs:
```bash
journalctl --disk-usage
```
```bash
journalctl --rotate
```
```bash
journalctl --vacuum-size=100M

# Clearing by date rang
# journalctl --vacuum-time=2d
```

<br/>

Clean unused dependencies:
```bash
# Could use autoremove but purge cleans config files as well
apt purge
```

<br/>

Clean outdated packages from apt cache:
```bash
apt-get autoclean
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

Confirm mounted disks:
```bash
df -h
```
