package policy

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

// Action is the rule action: allow ("in:") or exclude ("out:").
type Action int

const (
	ActionIn Action = iota
	ActionOut
)

func (a Action) String() string {
	switch a {
	case ActionIn:
		return "in"
	case ActionOut:
		return "out"
	}
	return "unknown"
}

// Namespace is the rule target type.
type Namespace int

const (
	NSHost Namespace = iota
	NSPath
	NSRepo
	NSContract
	NSMCP
)

func (n Namespace) String() string {
	switch n {
	case NSHost:
		return "host"
	case NSPath:
		return "path"
	case NSRepo:
		return "repo"
	case NSContract:
		return "contract"
	case NSMCP:
		return "mcp"
	}
	return "unknown"
}

// Mode controls how unpoliced destinations are handled.
type Mode int

const (
	ModeAdvisory Mode = iota // warn on unpoliced (default)
	ModeStrict               // block on unpoliced
)

func (m Mode) String() string {
	switch m {
	case ModeStrict:
		return "strict"
	case ModeAdvisory:
		return "advisory"
	}
	return "unknown"
}

// Rule is one parsed entry from a scope.txt file.
type Rule struct {
	Action    Action
	Namespace Namespace
	Pattern   string // the match pattern (with any namespace prefix stripped)
	Line      int    // 1-based source line number
	Raw       string // the original rule text (without the action keyword) for diagnostics
}

// Policy is a parsed scope.txt file.
type Policy struct {
	Mode   Mode
	Rules  []Rule
	SHA256 string // hex-encoded sha256 of the raw bytes; goes into the .jes predicate
	Raw    []byte // original file content
}

// ParseError describes a syntactic problem in a scope.txt file.
type ParseError struct {
	Line int
	Msg  string
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("scope.txt: line %d: %s", e.Line, e.Msg)
}

// Parse reads a scope.txt file from r and returns the resulting Policy.
func Parse(r io.Reader) (*Policy, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return ParseBytes(raw)
}

// ParseBytes parses a scope.txt file from a byte slice.
//
// The SHA-256 field is computed over the raw bytes exactly as provided.
// Callers are expected to supply LF-normalized content; CRLF-terminated
// files will produce a different (and incompatible) hash.
func ParseBytes(raw []byte) (*Policy, error) {
	p := &Policy{
		Mode: ModeAdvisory,
		Raw:  bytes.Clone(raw),
	}
	sum := sha256.Sum256(raw)
	p.SHA256 = hex.EncodeToString(sum[:])

	scanner := bufio.NewScanner(bytes.NewReader(raw))
	// Large policy files are uncommon but we should not truncate lines.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// mode: directive — may appear anywhere, last write wins.
		if strings.HasPrefix(line, "mode:") {
			val := strings.TrimSpace(line[len("mode:"):])
			switch val {
			case "strict":
				p.Mode = ModeStrict
			case "advisory":
				p.Mode = ModeAdvisory
			default:
				return nil, &ParseError{Line: lineNum, Msg: "mode must be 'strict' or 'advisory'"}
			}
			continue
		}

		// Rule lines: in: ... / out: ...
		var action Action
		var rest string
		switch {
		case strings.HasPrefix(line, "in:"):
			action = ActionIn
			rest = strings.TrimSpace(line[len("in:"):])
		case strings.HasPrefix(line, "out:"):
			action = ActionOut
			rest = strings.TrimSpace(line[len("out:"):])
		default:
			return nil, &ParseError{Line: lineNum, Msg: "line must start with 'in:', 'out:', 'mode:', or '#'"}
		}

		if rest == "" {
			return nil, &ParseError{Line: lineNum, Msg: "missing rule value"}
		}

		// Strip inline comments introduced by ' #' (space then hash).
		if i := strings.Index(rest, " #"); i >= 0 {
			rest = strings.TrimSpace(rest[:i])
		}

		ns, pattern := classify(rest)
		p.Rules = append(p.Rules, Rule{
			Action:    action,
			Namespace: ns,
			Pattern:   pattern,
			Line:      lineNum,
			Raw:       rest,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return p, nil
}

// classify decides which namespace a rule value belongs to and returns the
// normalized pattern (with any namespace prefix stripped).
//
// Dispatch is by shape, in order of specificity:
//
//	"path:<glob>"             -> NSPath
//	"mcp:<server>[:<tool>]"   -> NSMCP
//	"<chain>:0x<hex>"         -> NSContract
//	"<org>/<repo>" (no '.' and no ':')  -> NSRepo
//	anything else             -> NSHost
//
// Shape-based dispatch means scope.txt requires no explicit namespace
// declarations for the common cases; users just write what they mean.
func classify(value string) (Namespace, string) {
	switch {
	case strings.HasPrefix(value, "path:"):
		return NSPath, value[len("path:"):]
	case strings.HasPrefix(value, "mcp:"):
		return NSMCP, value
	case looksLikeContract(value):
		return NSContract, value
	case looksLikeRepo(value):
		return NSRepo, value
	default:
		return NSHost, value
	}
}

// looksLikeContract returns true if value has the shape "<chain>:0x<hex>".
func looksLikeContract(value string) bool {
	colon := strings.Index(value, ":")
	if colon <= 0 {
		return false
	}
	rest := value[colon+1:]
	if !strings.HasPrefix(rest, "0x") && !strings.HasPrefix(rest, "0X") {
		return false
	}
	hexPart := rest[2:]
	if hexPart == "" {
		return false
	}
	for i := 0; i < len(hexPart); i++ {
		if !isHexChar(hexPart[i]) {
			return false
		}
	}
	return true
}

// looksLikeRepo returns true if value has the shape "<org>/<repo>" with no
// dot (to distinguish from a domain) and no colon (to distinguish from
// MCP/contract forms).
func looksLikeRepo(value string) bool {
	if strings.ContainsAny(value, ".:") {
		return false
	}
	if !strings.Contains(value, "/") {
		return false
	}
	parts := strings.Split(value, "/")
	if len(parts) != 2 {
		return false
	}
	return parts[0] != "" && parts[1] != ""
}

func isHexChar(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}
