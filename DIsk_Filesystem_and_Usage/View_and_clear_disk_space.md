Run as root/sudo

<br/>

# Viewing Usage

<br/>

Get usage of root dir (1 level deep): 
```bash
du -chd / 2>/dev/null | sort -rhk 1 | head -5
```

<br />

Viewing largest files in dir with ls (2 ways):
```bash
 ls -halS | awk '{ print $5,$9}' | head
 ```
```bash
ls -hal | awk '{ print $5,$9 }' | sort -rhk 1 | head | column -s ' ' -t
```


<br />

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

# Clearing by date range
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


