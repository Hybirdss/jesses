package attest

import "os"

// writeFile writes data atomically to path. It writes to a temp file
// in the same directory and renames into place so a crashed writer
// cannot leave a half-formed .jes on disk.
func writeFile(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// readFile is a thin wrapper for symmetry with writeFile.
func readFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}
