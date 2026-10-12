package recording

import (
	"fmt"
	"syscall"
)

// minFreeDisk leaves room for the system, small cloud disks rarely have more.
const minFreeDisk = 512 << 20

func checkDiskSpace(path string) error {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return fmt.Errorf("statfs failed: %w", err)
	}

	if stat.Bsize <= 0 {
		return fmt.Errorf("statfs returned negative block size: %d", stat.Bsize)
	}

	freeBytes := stat.Bavail * uint64(stat.Bsize)
	if freeBytes < minFreeDisk {
		return fmt.Errorf("low disk space: %d bytes free", freeBytes)
	}
	return nil
}
