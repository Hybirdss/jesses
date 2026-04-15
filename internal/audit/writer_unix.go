//go:build !windows

package audit

import "syscall"

// lockFile acquires an exclusive advisory lock on the given file descriptor
// using flock(2). Blocks until the lock is available.
func lockFile(fd int) error {
	return syscall.Flock(fd, syscall.LOCK_EX)
}

// unlockFile releases an advisory lock held on the given file descriptor.
func unlockFile(fd int) error {
	return syscall.Flock(fd, syscall.LOCK_UN)
}
