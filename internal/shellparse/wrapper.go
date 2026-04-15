package shellparse

// wrapperTable is the FROZEN list of commands treated as wrappers —
// commands whose tail argv is the command that actually runs. The
// wrapper sets ambient state (uid, working dir, cgroup, env, time
// limit, scheduling) and then hands control to the tail.
//
// This list is part of the canonical extraction invariant. Adding or
// removing an entry changes Argv output for matching commands and
// therefore changes the destinations that downstream extractors emit.
// Because those destinations are committed into canonical Event hashes
// in the Merkle log, any change here requires a coordinated spec
// version bump (v0.1 → v0.2 predicate URI).
//
// Entries are names as they appear in argv[0]. Wrappers that require
// flag-specific positional consumption (sudo -u USER, timeout DURATION,
// env NAME=VALUE, chroot DIR) are handled by their own stopFn.
var wrapperTable = map[string]stopFn{
	"sudo":    stopSudo,
	"env":     stopEnv,
	"time":    stopFlagsOnly,
	"nice":    stopFlagsOnly,
	"timeout": stopTimeout,
	"stdbuf":  stopFlagsOnly,
	"xargs":   stopFlagsOnly,
	"nohup":   stopFlagsOnly,
	"exec":    stopFlagsOnly,
	"setsid":  stopFlagsOnly,
	"ionice":  stopFlagsOnly,
	"chroot":  stopChroot,
	"unshare": stopFlagsOnly,
}

// stopFn advances i past the wrapper's own flags/arguments and returns
// the index of the first token belonging to the tail (wrapped) command.
type stopFn func(argv []string, i int) int

// unwrapWrappers peels leading wrapper commands from argv.
// Returns the effective argv (everything after the last wrapper) and
// the wrapper commands in source order, each entry holding the wrapper
// name plus its own flags joined by spaces ("timeout -k 5 30").
//
// Peeling is left-to-right and terminates the moment argv[i] is not in
// wrapperTable. Nested wrappers compose: "sudo env X=y timeout 30 curl"
// yields Wrappers=["sudo", "env X=y", "timeout 30"], Argv=["curl", ...].
func unwrapWrappers(argv []string) (tail []string, wrappers []string) {
	i := 0
	for i < len(argv) {
		stop, ok := wrapperTable[argv[i]]
		if !ok {
			break
		}
		start := i
		next := stop(argv, i+1)
		if next > len(argv) {
			next = len(argv)
		}
		wrappers = append(wrappers, joinArgv(argv[start:next]))
		i = next
	}
	if i >= len(argv) {
		return nil, wrappers
	}
	return argv[i:], wrappers
}

// stopFlagsOnly consumes a run of - or -- prefixed flags, stopping at
// the first non-flag. Covers wrappers that don't take positional args
// of their own (time, nice, nohup, exec, setsid, ionice, stdbuf, xargs,
// unshare when used in its simple forms).
func stopFlagsOnly(argv []string, i int) int {
	for i < len(argv) {
		a := argv[i]
		if a == "--" {
			return i + 1
		}
		if len(a) == 0 || a[0] != '-' {
			return i
		}
		i++
	}
	return i
}

// stopSudo handles sudo's flags, including the short options that
// consume the following token (-u USER, -g GROUP, -D DIR, -p PROMPT,
// -C FD, -r ROLE, -t TYPE, -h HOST, -U USER).
func stopSudo(argv []string, i int) int {
	for i < len(argv) {
		a := argv[i]
		if a == "--" {
			return i + 1
		}
		if len(a) == 0 || a[0] != '-' {
			return i
		}
		if sudoConsumesNext(a) && i+1 < len(argv) {
			i += 2
			continue
		}
		i++
	}
	return i
}

// sudoConsumesNext reports whether a sudo short option takes the next
// argv token as its value.
func sudoConsumesNext(a string) bool {
	if len(a) != 2 || a[0] != '-' {
		return false
	}
	switch a[1] {
	case 'u', 'g', 'D', 'p', 'C', 'r', 't', 'h', 'U':
		return true
	}
	return false
}

// stopEnv handles `env [-iv] [-u NAME] [NAME=VALUE]... [COMMAND ARG...]`.
// It consumes flags, -u NAME pairs, and any NAME=VALUE assignments,
// stopping at the first token that is neither a flag nor an assignment.
func stopEnv(argv []string, i int) int {
	for i < len(argv) {
		a := argv[i]
		if a == "--" {
			return i + 1
		}
		if len(a) > 1 && a[0] == '-' {
			if a == "-u" || a == "-S" {
				if i+1 < len(argv) {
					i += 2
					continue
				}
			}
			i++
			continue
		}
		if isEnvAssignment(a) {
			i++
			continue
		}
		return i
	}
	return i
}

// stopTimeout handles `timeout [OPTIONS] DURATION COMMAND [ARG...]`.
// Options may include -s/-k with an argument. After flags, exactly
// one token (DURATION) is consumed before COMMAND.
func stopTimeout(argv []string, i int) int {
	for i < len(argv) {
		a := argv[i]
		if a == "--" {
			return i + 1
		}
		if len(a) > 0 && a[0] == '-' {
			if a == "-s" || a == "-k" || a == "--signal" || a == "--kill-after" {
				if i+1 < len(argv) {
					i += 2
					continue
				}
			}
			i++
			continue
		}
		// first non-flag token is DURATION - skip it
		return i + 1
	}
	return i
}

// stopChroot handles `chroot [OPTIONS] NEWROOT [COMMAND [ARG]...]`.
// After optional flags one positional token (NEWROOT) is consumed.
func stopChroot(argv []string, i int) int {
	for i < len(argv) {
		a := argv[i]
		if a == "--" {
			return i + 1
		}
		if len(a) > 0 && a[0] == '-' {
			i++
			continue
		}
		return i + 1
	}
	return i
}

// joinArgv concatenates parts with single spaces. The Wrappers list
// uses this so that a multi-token wrapper ("timeout -k 5 30") renders
// as one human-readable string.
func joinArgv(parts []string) string {
	switch len(parts) {
	case 0:
		return ""
	case 1:
		return parts[0]
	}
	n := len(parts) - 1
	for _, p := range parts {
		n += len(p)
	}
	b := make([]byte, 0, n)
	for i, p := range parts {
		if i > 0 {
			b = append(b, ' ')
		}
		b = append(b, p...)
	}
	return string(b)
}
