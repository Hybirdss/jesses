package shellparse

// reentryShells is the FROZEN set of programs that accept a shell
// payload via -c. Any argv[0] in this set followed by a -c flag with
// a payload triggers recursive tokenize+split of the payload.
//
// The set intentionally includes common absolute-path variants so that
// `/bin/bash -c` is detected even when the hook sees an absolute PATH
// lookup rather than a bare name. Adding a new shell here changes
// extraction output and therefore requires a spec version bump.
//
// NOT in this set on purpose:
//
//	python / python3 / ruby / perl / node — these accept `-c` or `-e`
//	but the payload is language code, not shell syntax. A dedicated
//	per-language extractor is the right layer for those (v0.2 work).
var reentryShells = map[string]bool{
	"bash":                true,
	"sh":                  true,
	"dash":                true,
	"zsh":                 true,
	"ksh":                 true,
	"/bin/bash":           true,
	"/bin/sh":             true,
	"/bin/dash":           true,
	"/bin/zsh":            true,
	"/bin/ksh":            true,
	"/usr/bin/bash":       true,
	"/usr/bin/sh":         true,
	"/usr/bin/dash":       true,
	"/usr/bin/zsh":        true,
	"/usr/bin/ksh":        true,
	"/usr/local/bin/bash": true,
	"/usr/local/bin/sh":   true,
}

// reentryPayload detects shell-via-string invocations in argv and
// returns the recursively parsed payload commands.
//
// Recognized forms:
//
//	bash -c PAYLOAD [ARG0 [ARG...]]
//	sh -c PAYLOAD
//	bash -xc PAYLOAD              (merged short flags containing 'c')
//	bash -- -c PAYLOAD            (after --, next is payload if preceded by -c)
//	eval PAYLOAD [PAYLOAD...]     (all remaining argv joined with spaces)
//
// Non-recognized forms (return nil, no error):
//
//	bash script.sh                (running a file, not -c payload)
//	python -c "print(1)"          (not a shell)
//	sh                            (interactive shell, no payload)
//
// The returned commands are parsed at Depth+1 with Origin set to
// "bash-c" or "eval" so the audit tree preserves the boundary.
func reentryPayload(argv []string, depth int) ([]Command, error) {
	if len(argv) == 0 {
		return nil, nil
	}
	head := argv[0]

	if head == "eval" {
		if len(argv) < 2 {
			return nil, nil
		}
		return reparseBody(joinArgv(argv[1:]), depth+1, "eval")
	}

	if !reentryShells[head] {
		return nil, nil
	}

	for i := 1; i < len(argv); i++ {
		a := argv[i]
		if a == "-c" {
			if i+1 >= len(argv) {
				return nil, nil
			}
			return reparseBody(argv[i+1], depth+1, "bash-c")
		}
		if len(a) > 1 && a[0] == '-' && a[1] != '-' && containsByte(a, 'c') {
			if i+1 >= len(argv) {
				return nil, nil
			}
			return reparseBody(argv[i+1], depth+1, "bash-c")
		}
		if len(a) > 0 && a[0] == '-' {
			// other flag, keep scanning
			continue
		}
		// non-flag non-c reached: this is a script path, not -c payload
		return nil, nil
	}
	return nil, nil
}

// containsByte is a tiny helper to avoid a strings import for a single
// character scan.
func containsByte(s string, c byte) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return true
		}
	}
	return false
}
