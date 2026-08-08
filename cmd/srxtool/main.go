// Command srxtool is the pure command-line equivalent of the original
// Python scripts (`python3 srxaudit.py conf.xml --json audit.json`): no
// HTTP server, no Docker, no graphical interface. Each subcommand reads a
// conf file and writes its results to stdout or to the files requested by
// flags.
//
// It's a thin CLI wrapper over the business packages (internal/config,
// internal/inventory, internal/audit, internal/rules): no logic is
// duplicated here, only flag parsing and file writing.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/local/srxtool-go/internal/audit"
	"github.com/local/srxtool-go/internal/config"
	"github.com/local/srxtool-go/internal/inventory"
	"github.com/local/srxtool-go/internal/junosname"
	"github.com/local/srxtool-go/internal/rules"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "inventory":
		err = runInventory(os.Args[2:])
	case "audit":
		err = runAudit(os.Args[2:])
	case "rename-suggest":
		err = runRenameSuggest(os.Args[2:])
	case "rename-apply":
		err = runRenameApply(os.Args[2:])
	case "cleanup":
		err = runCleanup(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		printErr(err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `srxtool — audit, inventory, and rule management for Juniper SRX configurations
in pure command-line form (no server, no Docker required).

Usage:
  srxtool inventory <conf> [--json out.json] [--xlsx out.xlsx] [--allow-empty]
  srxtool audit     <conf> [--json out.json] [--xlsx out.xlsx] [--fix out.set] [--min-severity SEV] [--allow-empty]
  srxtool rename-suggest <conf> [--dns] [--csv out.csv]
  srxtool rename-apply   <conf> --map plan.csv [--set out.set] [--rollback out.set]
  srxtool cleanup --inventory inv.json --hitcount hits.xml
                  [--only glob] [--exclude glob ...] [--include-deny] [--batch name]
                  [--set out.set] [--rollback out.set]

With no output flag, each subcommand prints its text report to stdout.
Adding --json/--xlsx/--fix/--csv/--set/--rollback also writes the
requested files, in addition to the text on stdout (use a redirection if
you only want the file: "srxtool audit conf.xml --json a.json > /dev/null").

Examples:
  srxtool audit config.xml
  srxtool audit config.xml --json audit.json --xlsx audit.xlsx --fix fix.set --min-severity HIGH
  srxtool inventory config.xml --json inv.json
  srxtool rename-suggest config.xml --csv rename-plan.csv
  srxtool rename-apply config.xml --map rename-plan.csv --set rename.set --rollback rename-rollback.set
  srxtool cleanup --inventory inv.json --hitcount hitcount.xml --set cleanup.set
`)
}

// printErr prints a message suited to the error type, never echoing back
// internal detail (system file path, stack) — same policy as internal/api
// (see task 05).
func printErr(err error) {
	var un *junosname.UnsafeNameError
	var fe *config.FormatError
	switch {
	case errors.As(err, &un):
		fmt.Fprintf(os.Stderr, "error: a name contains an unsafe character (%v)\n", err)
	case errors.As(err, &fe):
		fmt.Fprintf(os.Stderr, "format error: %v\n", err)
	default:
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
	}
}

// reorderArgs places arguments not starting with "-" AFTER all the
// arguments that do — the stdlib's flag package stops at the first
// positional argument it encounters and treats everything else as
// positional, which makes `srxtool audit conf.xml --json f` invalid
// without this reordering (the conf file is naturally typed before the
// flags by shell reflex). Doesn't handle flags whose value is attached
// via a space after a lone "-" (not used by this program), which is
// sufficient for every flag defined here.
func reorderArgs(args []string) []string {
	var flags, positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			flags = append(flags, a)
			// Boolean flags (--dns, --allow-empty, --include-deny) don't
			// consume the next argument; value flags (--json f, --only
			// glob, ...) do. We can't know which without a FlagSet here, so
			// we only consume the next argument if it does NOT start with
			// "-" AND it isn't the last element of a pair already
			// consumed: a correct heuristic for every flag in this program
			// (none of them take a value starting with "-").
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") && !isKnownBoolFlag(a) {
				i++
				flags = append(flags, args[i])
			}
			continue
		}
		positional = append(positional, a)
	}
	return append(flags, positional...)
}

func isKnownBoolFlag(name string) bool {
	switch strings.TrimLeft(name, "-") {
	case "dns", "allow-empty", "include-deny", "h", "help":
		return true
	default:
		return false
	}
}

// --- shared helpers --------------------------------------------------

func readConf(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("unable to read %s: %w", path, err)
	}
	return data, nil
}

func writeFile(path string, data []byte) error {
	if path == "" {
		return nil
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("unable to write %s: %w", path, err)
	}
	fmt.Fprintf(os.Stderr, "written: %s\n", path)
	return nil
}

// --- inventory ----------------------------------------------------------

func runInventory(args []string) error {
	fs := flag.NewFlagSet("inventory", flag.ExitOnError)
	jsonOut := fs.String("json", "", "also write the inventory JSON to this file")
	xlsxOut := fs.String("xlsx", "", "also write the XLSX workbook to this file")
	allowEmpty := fs.Bool("allow-empty", false, "don't fail on an empty model")
	fs.Parse(reorderArgs(args))
	if fs.NArg() != 1 {
		return errors.New("usage: srxtool inventory <conf> [--json f] [--xlsx f] [--allow-empty]")
	}

	data, err := readConf(fs.Arg(0))
	if err != nil {
		return err
	}
	m, err := config.Parse(data, config.Options{AllowEmpty: *allowEmpty})
	if err != nil {
		return err
	}
	res := inventory.Build(m)

	fmt.Println(res.ReportText())

	if *jsonOut != "" {
		b, err := res.JSON()
		if err != nil {
			return err
		}
		if err := writeFile(*jsonOut, b); err != nil {
			return err
		}
	}
	if *xlsxOut != "" {
		f, err := os.Create(*xlsxOut)
		if err != nil {
			return fmt.Errorf("unable to create %s: %w", *xlsxOut, err)
		}
		defer f.Close()
		if err := res.ExportXLSX(f); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "written: %s\n", *xlsxOut)
	}
	return nil
}

// --- audit ----------------------------------------------------------------

func runAudit(args []string) error {
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	jsonOut := fs.String("json", "", "also write the findings JSON to this file")
	xlsxOut := fs.String("xlsx", "", "also write the XLSX workbook to this file")
	fixOut := fs.String("fix", "", "also write the set/delete fixes to this file")
	minSevFlag := fs.String("min-severity", "INFO", "minimum severity to keep (CRITICAL/HIGH/MEDIUM/LOW/INFO)")
	allowEmpty := fs.Bool("allow-empty", false, "don't fail on an empty model")
	fs.Parse(reorderArgs(args))
	if fs.NArg() != 1 {
		return errors.New("usage: srxtool audit <conf> [--json f] [--xlsx f] [--fix f] [--min-severity SEV] [--allow-empty]")
	}

	minSev, ok := parseSeverity(*minSevFlag)
	if !ok {
		return fmt.Errorf("invalid --min-severity: %q (expected CRITICAL/HIGH/MEDIUM/LOW/INFO)", *minSevFlag)
	}

	data, err := readConf(fs.Arg(0))
	if err != nil {
		return err
	}
	m, err := config.Parse(data, config.Options{AllowEmpty: *allowEmpty})
	if err != nil {
		return err
	}
	findings, err := audit.Run(m)
	if err != nil {
		return err
	}
	findings = audit.FilterMinSeverity(findings, minSev)

	fmt.Println(audit.ReportText(findings, m))

	if *jsonOut != "" {
		b, err := audit.FindingsJSON(findings)
		if err != nil {
			return err
		}
		if err := writeFile(*jsonOut, b); err != nil {
			return err
		}
	}
	if *fixOut != "" {
		if err := writeFile(*fixOut, []byte(audit.FixText(findings))); err != nil {
			return err
		}
	}
	if *xlsxOut != "" {
		f, err := os.Create(*xlsxOut)
		if err != nil {
			return fmt.Errorf("unable to create %s: %w", *xlsxOut, err)
		}
		defer f.Close()
		if err := audit.ExportXLSX(findings, f); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "written: %s\n", *xlsxOut)
	}
	return nil
}

func parseSeverity(v string) (audit.Severity, bool) {
	switch strings.ToUpper(v) {
	case "CRITICAL":
		return audit.Critical, true
	case "HIGH":
		return audit.High, true
	case "MEDIUM":
		return audit.Medium, true
	case "LOW":
		return audit.Low, true
	case "INFO":
		return audit.Info, true
	default:
		return "", false
	}
}

// --- rename-suggest ---------------------------------------------------------

func runRenameSuggest(args []string) error {
	fs := flag.NewFlagSet("rename-suggest", flag.ExitOnError)
	useDNS := fs.Bool("dns", false, "suggest a name via reverse DNS (PTR) when possible")
	csvOut := fs.String("csv", "", "write the plan's CSV to this file (otherwise: stdout)")
	fs.Parse(reorderArgs(args))
	if fs.NArg() != 1 {
		return errors.New("usage: srxtool rename-suggest <conf> [--dns] [--csv f]")
	}

	data, err := readConf(fs.Arg(0))
	if err != nil {
		return err
	}
	m, err := config.Parse(data, config.Options{})
	if err != nil {
		return err
	}
	inv := inventory.Build(m)
	candidates := rules.DetectIPNamedObjects(inv, m)

	var out *os.File
	if *csvOut != "" {
		out, err = os.Create(*csvOut)
		if err != nil {
			return fmt.Errorf("unable to create %s: %w", *csvOut, err)
		}
		defer out.Close()
	} else {
		out = os.Stdout
	}
	if err := rules.WriteSuggestCSV(candidates, *useDNS, out); err != nil {
		return err
	}
	if *csvOut != "" {
		fmt.Fprintf(os.Stderr, "written: %s (%d IP-named object(s) detected)\n", *csvOut, len(candidates))
	}
	return nil
}

// --- rename-apply -----------------------------------------------------------

func runRenameApply(args []string) error {
	fs := flag.NewFlagSet("rename-apply", flag.ExitOnError)
	mapFile := fs.String("map", "", "filled-in CSV (new_name column), required")
	setOut := fs.String("set", "", "write the set/delete commands to this file (otherwise: stdout)")
	rollbackOut := fs.String("rollback", "", "write the rollback to this file")
	fs.Parse(reorderArgs(args))
	if fs.NArg() != 1 || *mapFile == "" {
		return errors.New("usage: srxtool rename-apply <conf> --map plan.csv [--set f] [--rollback f]")
	}

	data, err := readConf(fs.Arg(0))
	if err != nil {
		return err
	}
	m, err := config.Parse(data, config.Options{})
	if err != nil {
		return err
	}
	inv := inventory.Build(m)
	candidates := rules.DetectIPNamedObjects(inv, m)

	mapData, err := readConf(*mapFile)
	if err != nil {
		return err
	}
	mapping, rejected, err := rules.ReadRenameMapCSV(strings.NewReader(string(mapData)))
	if err != nil {
		return fmt.Errorf("unable to read CSV %s: %w", *mapFile, err)
	}
	for _, r := range rejected {
		fmt.Fprintf(os.Stderr, "line ignored: %s\n", r)
	}
	if len(mapping) == 0 {
		return errors.New("no valid line with a new_name in the supplied CSV")
	}

	setCmds, rollback, err := rules.ApplyRenameMap(candidates, mapping)
	if err != nil {
		return err
	}

	setText := strings.Join(setCmds, "\n") + "\n"
	if *setOut != "" {
		if err := writeFile(*setOut, []byte(setText)); err != nil {
			return err
		}
	} else {
		fmt.Print(setText)
	}
	if *rollbackOut != "" {
		if err := writeFile(*rollbackOut, []byte(strings.Join(rollback, "\n")+"\n")); err != nil {
			return err
		}
	}
	return nil
}

// --- cleanup ------------------------------------------------------------

// cleanupStrings implements flag.Value to accumulate several --exclude.
type cleanupStrings []string

func (s *cleanupStrings) String() string { return strings.Join(*s, ",") }
func (s *cleanupStrings) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func runCleanup(args []string) error {
	fs := flag.NewFlagSet("cleanup", flag.ExitOnError)
	invFile := fs.String("inventory", "", "inventory JSON (produced by 'srxtool inventory --json'), required")
	hitFile := fs.String("hitcount", "", "hit-count export (XML or CLI text), required")
	only := fs.String("only", "", "glob pattern for candidate rules (default: *)")
	includeDeny := fs.Bool("include-deny", false, "also include deny/reject rules with 0 hits")
	batch := fs.String("batch", "", "batch name (banner of generated files)")
	setOut := fs.String("set", "", "write the removal commands to this file (otherwise: stdout)")
	rollbackOut := fs.String("rollback", "", "write the rollback to this file")
	var exclude cleanupStrings
	fs.Var(&exclude, "exclude", "glob pattern to exclude (repeatable)")
	fs.Parse(reorderArgs(args))
	if *invFile == "" || *hitFile == "" {
		return errors.New("usage: srxtool cleanup --inventory inv.json --hitcount hits.xml [--only glob] [--exclude glob ...] [--include-deny] [--set f] [--rollback f]")
	}

	invData, err := readConf(*invFile)
	if err != nil {
		return err
	}
	var invPayload struct {
		Policies []rules.CleanupPolicy `json:"policies"`
	}
	if err := json.Unmarshal(invData, &invPayload); err != nil {
		return fmt.Errorf("invalid inventory JSON (%s): %w", *invFile, err)
	}

	hitData, err := readConf(*hitFile)
	if err != nil {
		return err
	}
	hits, err := rules.ParseHitcount(strings.NewReader(string(hitData)))
	if err != nil {
		return fmt.Errorf("unreadable hit-count export (%s): %w", *hitFile, err)
	}

	res, err := rules.Cleanup(invPayload.Policies, hits, rules.CleanupOptions{
		Only: *only, Exclude: exclude, IncludeDeny: *includeDeny, Batch: *batch,
	})
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "candidates for removal: %d\ndeny/reject kept: %d\nexcluded: %d\nignored (no hit-count): %d\n",
		len(res.Candidates), len(res.KeptDeny), len(res.Excluded), len(res.Unknown))

	setText := strings.Join(res.SetCommands, "\n") + "\n"
	if *setOut != "" {
		if err := writeFile(*setOut, []byte(setText)); err != nil {
			return err
		}
	} else {
		fmt.Print(setText)
	}
	if *rollbackOut != "" {
		if err := writeFile(*rollbackOut, []byte(strings.Join(res.Rollback, "\n")+"\n")); err != nil {
			return err
		}
	}
	return nil
}
