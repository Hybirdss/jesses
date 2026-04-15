// Command jesses is the reference CLI.
//
// Subcommands:
//
//	jesses verify <file.jes>       — run 6-gate verification
//	jesses view   <file.jes>       — render timeline in browser (60s TTL)
//	jesses run    -- <cmd> [args]  — wrap one command, emit a .jes
//	jesses hook                    — stdin-driven hook for agent harnesses
//	jesses init-scope              — scaffold a scope.txt in cwd
//	jesses version                 — print version string
//
// The CLI is deliberately small. Every subcommand delegates to a
// single function in the internal packages and formats the output.
// Flags are stdlib `flag` package only — no dependency on cobra or
// kingpin, to keep the binary static and auditable.
package main

import (
	"fmt"
	"os"
)

// Version is the CLI version string. Baked in at build time via
// ldflags in release builds; defaults to "dev" for local work.
var Version = "dev"

func main() {
	if len(os.Args) < 2 {
		printUsage(os.Stderr)
		os.Exit(2)
	}

	switch os.Args[1] {
	case "verify":
		os.Exit(runVerify(os.Args[2:]))
	case "view":
		os.Exit(runView(os.Args[2:]))
	case "run":
		os.Exit(runRun(os.Args[2:]))
	case "hook":
		os.Exit(runHook(os.Args[2:]))
	case "init-scope":
		os.Exit(runInitScope(os.Args[2:]))
	case "version", "--version", "-v":
		fmt.Println(Version)
		os.Exit(0)
	case "help", "--help", "-h":
		printUsage(os.Stdout)
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "jesses: unknown subcommand %q\n\n", os.Args[1])
		printUsage(os.Stderr)
		os.Exit(2)
	}
}

func printUsage(w *os.File) {
	fmt.Fprintln(w, `jesses — cryptographic attestation for LLM agent actions

Usage: jesses <subcommand> [arguments]

Subcommands:
  verify     run 6-gate verification on a .jes envelope
  view       render a .jes timeline in a local browser (60s TTL)
  run        wrap one shell command and emit a .jes attestation
  hook       stdin-driven hook mode for agent harnesses
  init-scope scaffold a scope.txt in the current directory
  version    print version string

Run 'jesses <subcommand> --help' for subcommand-specific flags.`)
}
