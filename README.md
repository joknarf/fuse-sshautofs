# sshautofs
fuse automount sshfs filesystems

# Prerequisites
* fuse sshfs
* fuse3
  
# Example
```
$ sshautofs ~/servers
$ cd ~/servers/myhost
```
Automatically mounts `sshfs host:/ ~/servers-ssh/myhost` accessible through `~/servers/myhost` symlink
the mount is expiring by default after 10min, the sshfs will be unmounted if not in used.
