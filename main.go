package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
)

// sshAutoFS implements a FUSE FS that shows a symlink for each host directory,
// and mounts sshfs on access.
type sshAutoFS struct {
	mntRoot   string // e.g. /home/user/mnt
	sshfsRoot string // e.g. /home/user/mnt-ssh
	sshConfig string // Path to ssh config file, if any
	sshfsOpts string // Additional sshfs options
}

var _ fs.FS = (*sshAutoFS)(nil)

func (fsys *sshAutoFS) Root() (fs.Node, error) {
	return &autoDir{fsys: fsys}, nil
}

type autoDir struct {
	fsys *sshAutoFS
}

var _ fs.Node = (*autoDir)(nil)
var _ fs.Handle = (*autoDir)(nil)
var _ fs.NodeStringLookuper = (*autoDir)(nil)
var _ fs.HandleReadDirAller = (*autoDir)(nil)

func (d *autoDir) Attr(ctx context.Context, a *fuse.Attr) error {
	a.Inode = 1
	a.Mode = os.ModeDir | 0500
	a.Mtime = time.Now()
	a.Ctime = time.Now()
	a.Uid = uint32(os.Getuid())
	a.Gid = uint32(os.Getgid())
	a.Size = 4096
	a.Blocks = 1
	return nil
}

// List all host symlinks (all directories in sshfsRoot)
func (d *autoDir) ReadDirAll(ctx context.Context) ([]fuse.Dirent, error) {
	entries := []fuse.Dirent{
		{Inode: 1, Name: ".", Type: fuse.DT_Dir},
		{Inode: 1, Name: "..", Type: fuse.DT_Dir},
	}
	files, err := os.ReadDir(d.fsys.sshfsRoot)
	if err == nil {
		for _, f := range files {
			if f.IsDir() {
				entries = append(entries, fuse.Dirent{Inode: 2, Name: f.Name(), Type: fuse.DT_Link})
			}
		}
	}
	return entries, nil
}

// On lookup, if host dir, ensure sshfs is mounted, then return a symlink node
func (d *autoDir) Lookup(ctx context.Context, name string) (fs.Node, error) {
	hostname := strings.Split(name, "/")[0]
	if strings.HasPrefix(hostname, ".") || hostname == "" {
		return nil, syscall.ENOENT // No such file or directory
	}
	mntTarget := filepath.Join(d.fsys.sshfsRoot, hostname)

	// If not mounted, mount it
	if !isDirMounted(mntTarget) {
		err := os.MkdirAll(mntTarget, 0700)
		if err != nil {
			return nil, syscall.EIO
		}
		sshfsargs := []string{fmt.Sprintf("%s:/", hostname), mntTarget, "-o", d.fsys.sshfsOpts}
		log.Println("Mounting sshfs for host:", hostname, "at", mntTarget, "with sshConfig:", d.fsys.sshConfig)
		if d.fsys.sshConfig != "" {
			sshfsargs = append(sshfsargs, []string{"-F", d.fsys.sshConfig}...)
		}
		sshfsCmd := exec.Command("sshfs", sshfsargs...)
		sshfsCmd.Env = os.Environ()
		if err := sshfsCmd.Run(); err != nil {
			// If mount failed, remove the directory so the symlink does not appear
			log.Println("err:", err)
			os.Remove(mntTarget)
			return nil, syscall.EIO
		}
	}
	// Update last access time for this mount
	updateMountAccess(mntTarget)
	// Return a symlink node
	return &symlinkNode{
		name:   name,
		target: mntTarget,
	}, nil
}

// Map to track last access time for each mount
var mountAccessMu sync.Mutex
var mountAccess = make(map[string]time.Time)

// updateMountAccess records the last access time for a mount
func updateMountAccess(mnt string) {
	mountAccessMu.Lock()
	mountAccess[mnt] = time.Now()
	mountAccessMu.Unlock()
}

// background goroutine to unmount unused sshfs mounts after timeout
func startUnmountWorker(timeout time.Duration) {
	go func() {
		for {
			time.Sleep(10 * time.Second)
			now := time.Now()
			mountAccessMu.Lock()
			for mnt, last := range mountAccess {
				age := now.Sub(last)
				if age > timeout {
					if isDirMounted(mnt) {
						err := exec.Command("fusermount", "-u", mnt).Run()
						if err != nil {
							//log.Printf("Failed to unmount (still busy?) %s: %v", mnt, err)
							mountAccess[mnt] = time.Now() // Re-update access time to prevent immediate unmount
							continue
						} else {
							log.Printf("Unmounted idle sshfs mount: %s", mnt)
						}
					}
					if err := os.Remove(mnt); err != nil {
						log.Printf("Failed to remove mountpoint %s: %v", mnt, err)
					}
					delete(mountAccess, mnt)
					log.Printf("Cleaned up idle sshfs mount entry: %s", mnt)
				}
			}
			mountAccessMu.Unlock()
		}
	}()
}

type symlinkNode struct {
	name   string
	target string
}

var _ fs.Node = (*symlinkNode)(nil)
var _ fs.NodeReadlinker = (*symlinkNode)(nil)

func (s *symlinkNode) Attr(ctx context.Context, a *fuse.Attr) error {
	a.Inode = 2
	a.Mode = os.ModeSymlink | 0777
	a.Mtime = time.Now()
	a.Ctime = time.Now()
	a.Uid = uint32(os.Getuid())
	a.Gid = uint32(os.Getgid())
	a.Size = uint64(len(s.target))
	return nil
}

func (s *symlinkNode) Readlink(ctx context.Context, req *fuse.ReadlinkRequest) (string, error) {
	return s.target, nil
}

// isDirMounted checks if a directory is a mount point (by parsing /proc/mounts)
func isDirMounted(dir string) bool {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) >= 2 {
		}
		if len(fields) >= 2 && fields[1] == dir {
			return true
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("Error reading /proc/mounts: %v", err)
	}
	return false
}

func unmountAllSSHFS(sshfsRoot string) {
	files, err := os.ReadDir(sshfsRoot)
	if err != nil {
		return
	}
	for _, f := range files {
		if f.IsDir() {
			mnt := filepath.Join(sshfsRoot, f.Name())
			if isDirMounted(mnt) {
				log.Println("Unmounting sshfs mount:", mnt)
				exec.Command("fusermount", "-u", mnt).Run()
			}
			os.Remove(mnt)
		}
	}
}

func main() {
	sshConfig := flag.String("F", "", "ssh config file to use")
	timeout := flag.Duration("timeout", 10*time.Minute, "Timeout before unmounting unused sshfs mounts (e.g. 10m, 30s)")
	foreground := flag.Bool("foreground", false, "Run in foreground (do not daemonize)")
	opts := flag.String("o", "", "Additional sshfs options (e.g. -o reconnect,ro)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s <mountpoint>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  Example: %s ~/mnt\n", os.Args[0])
	}
	flag.Parse()
	sshConf := ""
	if *sshConfig != "" {
		var errF error
		sshConf, errF = filepath.Abs(*sshConfig)
		if errF != nil {
			log.Fatalf("Failed to resolve ssh config file: %v", errF)
		}
	}
	sshfsOpts := "LogLevel=ERROR,BatchMode=yes"
	if *opts != "" {
		sshfsOpts += "," + *opts
	}
	if flag.NArg() < 1 {
		log.Fatal("Mount point is required as a positional argument")
	}

	mntRoot, err := filepath.Abs(flag.Args()[0])
	if err != nil {
		log.Fatalf("Failed to resolve mount point: %v", err)
	}
	sshfsRoot := mntRoot + "-ssh"
	if err := os.MkdirAll(sshfsRoot, 0700); err != nil {
		log.Fatalf("Failed to create sshfs root: %v", err)
	}
	if !*foreground {
		// Fork and detach
		if os.Getppid() != 1 {
			exe, err := os.Executable()
			if err != nil {
				os.Exit(1)
			}
			attr := &os.ProcAttr{
				Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
				Env:   os.Environ(),
			}
			_, err = os.StartProcess(exe, append([]string{exe, "-foreground"}, os.Args[1:]...), attr)
			if err != nil {
				os.Exit(1)
			}
			os.Exit(0)
		}
		// Redirect output to /dev/null
		f, _ := os.OpenFile("/dev/null", os.O_RDWR, 0)
		os.Stdout = f
		os.Stderr = f
		log.SetOutput(f)
	}

	log.Printf("Attempting to mount sshautofs at %s\n", mntRoot)
	c, err := fuse.Mount(
		mntRoot,
		fuse.FSName("sshautofs"),
		fuse.Subtype("sshautofs"),
		//		fuse.WritebackCache(),
		//		fuse.MaxReadahead(1<<20),
		//		fuse.AsyncRead(),
	)
	if err != nil {
		log.Fatalf("Failed to mount: %v", err)
	}
	defer c.Close()

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-ch
		log.Println("Received interrupt, unmounting...")
		// Unmount all sshfs mounts before unmounting the FUSE fs
		unmountAllSSHFS(sshfsRoot)
		fuse.Unmount(mntRoot)
		os.Exit(0)
	}()

	// Start background unmount worker
	startUnmountWorker(*timeout)

	log.Println("sshautofs mounted successfully, serving...")
	err = fs.Serve(c, &sshAutoFS{mntRoot: mntRoot, sshfsRoot: sshfsRoot, sshConfig: sshConf, sshfsOpts: sshfsOpts})
	if err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
	unmountAllSSHFS(sshfsRoot)
	log.Println("Filesystem server stopped, exiting.")
}
