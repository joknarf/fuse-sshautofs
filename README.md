# sshautofs
fuse automount sshfs filesystems

* automatic access to servers filesystems through fuse-sshfs when accessing `<mountpoint>/<server>`
* use sshfs to automatically mount `sshfs <server>:/ <mountpoint>-ssh/<server>`
* creates symlink `<mountpoint>/<server> -> <mountpoint>-ssh/<server>` to access
* automatic unmount after timeout

## Prerequisites

* fuse sshfs
* fuse3
  
## Usage

```
$ sshautofs [-timeout=<duration>] [-F=<ssh_config_file>] [-foreground] <mountpoint>
```

## example
```
$ sshautofs ~/servers
$ cd ~/servers/myhost
```
Automatically mounts `sshfs myhost:/ ~/servers-ssh/myhost` accessible through `~/servers/myhost` symlink
the mount is expiring by default after 10min, the sshfs will be unmounted if not in used.

## Options

* `-timeout=1m` define expiration timeout to unmount sshfs
* `-F=~/ssh/autofs` define ssh config file to use for sshfs
* `-foreground` launch sshautofs in foreground (default daemonize)
