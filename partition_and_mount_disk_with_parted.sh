# Run as root/sudo

# List partitions (3ways): 
parted -l
lsblk -e7
cat /proc/partitions

# Enter parted session:
parted /dev/sdb

# Get partition info (use throughout):
print

#	Create partition table:
mklabel gpt

#	Create partition:
mkpart primary ext4 0% 100%

#	Quit parted session:
quit

#	List partitions again: Repeat step #1

#	Confirm that kernel has an updated view of anything that has been changed (avoids a reboot):
partprobe

#	Make filesystem from partition name:
mkfs -t ext4 /dev/sdb1

#	Get parition UUID (2 ways): 
blkid
lsblk -f

# Add to fstab (can also use partition name):
# UUID=1234 /dev/sdb1 ext4 defaults 0 0
