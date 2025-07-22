# sshautofs
fuse automount sshfs filesystems

* automatic access to servers filesystems through fuse-sshfs when accessing `<mountpoint>/<server>`
* use sshfs to automatically mount `sshfs <server>:/ <mountpoint>-ssh/<server>`
* creates symlink `<mountpoint>/<server> -> <mountpoint>-ssh/<server>` to access
* automatic unmount after timeout
* special cmd directory allow remote commands on servers

## Prerequisites

* fuse sshfs
* fuse3
  
## Usage

```
$ sshautofs [-timeout=<duration>] [-F <ssh_config_file>] [-o sshfsopts] [-foreground] [-cmd cmd="cmd args",...] <mountpoint>
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
$ cat ~/servers/cmd/myhost/ps
UID          PID    PPID  C STIME TTY          TIME CMD
root           1       0  0 Jul09 ?        00:00:06 /usr/lib/systemd/systemd --switched-root --system --deserialize 18
root           2       0  0 Jul09 ?        00:00:00 [kthreadd]
...
```

Automatically mounts `sshfs myhost:/ ~/servers-ssh/myhost` accessible through `~/servers/myhost` symlink  
the mount is expiring by default after 10min, the sshfs will be unmounted if not in use.  
In the special `cmd` directory, a cat `~/servers/cmd/myhost/ps` executes `ssh myhost 'ps -ef'` and display output

## Options

* `-timeout=1m` define expiration timeout to unmount sshfs
* `-F ~/ssh/autofs` define ssh config file to use for sshfs
* `-foreground` launch sshautofs in foreground (default daemonize)
* `-o ro,reconnect` sshfs -o options to pass
* `-cmd cmd='cmd args',... commands to expose in `cmd` special directory

