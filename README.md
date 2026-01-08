[![Joknarf Tools](https://img.shields.io/badge/Joknarf%20Tools-Visit-darkgreen?logo=github)](https://joknarf.github.io/joknarf-tools)
[![Build binary packages](https://github.com/joknarf/fuse-sshautofs/actions/workflows/release.yml/badge.svg)](https://github.com/joknarf/fuse-sshautofs/actions/workflows/release.yml)
[![go](https://img.shields.io/badge/lang-Go%20-blue.svg)]()
[![OS](https://img.shields.io/badge/OS-Linux%20-blue.svg)]()
[![Licence](https://img.shields.io/badge/licence-MIT-blue.svg)](https://shields.io/)
[![Packages](https://img.shields.io/badge/Packages-%20rpm%20|%20deb%20|%20pkg%20|%20apk%20|%20brew%20-darkgreen.svg)](https://github.com/joknarf/fuse-sshautofs/releases/latest)

# sshautofs
fuse automount sshfs filesystems  
Access any remote server filesystems through a `<hostname>` directory  
Remember OGFS ?

* automatic access to servers filesystems through fuse-sshfs when accessing `<mountpoint>/<server>`
  * transparently use sshfs to mount `sshfs <server>:/ <mountpoint>-ssh/<server>`
  * creates symlink `<mountpoint>/<server> -> <mountpoint>-ssh/<server>` to access
  * automatic unmount after timeout
* special cmd directory allow specific remote commands on servers

## Prerequisites

* fuse sshfs
* fuse3
  
## Usage

```
$ ./sshautofs
Usage: ./sshautofs [options] <mountpoint>
Example: ./sshautofs ~/mnt

Options:
  -F string
        ssh config file to use
  -cmd value
        Remote commands to expose in /cmd/<host>/<cmd> (e.g. -cmd ps='/bin/ps -ef' -cmd ...)
  -foreground
        Run in foreground (do not daemonize)
  -o string
        Additional sshfs options (e.g. -o reconnect,ro)
  -remote_path string
        Remote path to mount through sshfs (default "/")
  -timeout duration
        Timeout before unmounting unused sshfs mounts (e.g. 30s) (default 10m0s)
```

## Example

```
$ sshautofs -cmd ps='/bin/ps -ef' ~/servers
$ cd ~/servers/myhost
$ ls -l
lrwxrwxrwx. 1 root root          7 May  1  2023 bin -> usr/bin
drwxr-xr-x. 1 root root       4096 Apr  8  2024 bin.usr-is-merged
drwxr-xr-x. 1 root root       4096 Apr 18  2022 boot
drwxr-xr-x. 1 root root       3860 Jul 11 08:38 dev
drwxr-xr-x. 1 root root      12288 Jul 12 07:43 etc
drwxr-xr-x. 1 root root       4096 May  8 10:53 home
-rwxrwxrwx. 1 root root    2724480 Jun  9 20:32 init
...
$ tail ~/servers/myhost/var/log/messages
Jul 26 14:55:58 myhost systemd...
...
$ cat ~/servers/cmd/myhost/ps
UID          PID    PPID  C STIME TTY          TIME CMD
root           1       0  0 Jul09 ?        00:00:06 /usr/lib/systemd/systemd --switched-root --system --deserialize 18
root           2       0  0 Jul09 ?        00:00:00 [kthreadd]
...
$ grep chronyd ~/servers/cmd/myhost/ps
chrony       955       1  0 08:39 ?        00:00:00 /usr/sbin/chronyd
```

> * Automatically mounts `sshfs myhost:/ ~/servers-ssh/myhost` accessible through `~/servers/myhost` symlink  
> * the mount is expiring by default after 10min, the sshfs will be unmounted after 10min without access.  
> * In the special `cmd` directory, a cat `~/servers/cmd/myhost/ps` executes `ssh myhost 'ps -ef'` and display output

