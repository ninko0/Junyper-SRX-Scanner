package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// buildCLI compiles the binary once for the whole suite.
func buildCLI(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "srxtool")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Dir = "."
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("CLI build: %v\n%s", err, out)
	}
	return bin
}

func run(t *testing.T, bin string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	code = 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatalf("execution: %v", err)
		}
	}
	return outBuf.String(), errBuf.String(), code
}

const fixtures = "../../testdata/fixtures"

func TestNoArgsShowsUsage(t *testing.T) {
	bin := buildCLI(t)
	_, stderr, code := run(t, bin)
	if code != 2 {
		t.Fatalf("code = %d, expected 2", code)
	}
	if !strings.Contains(stderr, "srxtool") {
		t.Errorf("expected usage on stderr: %q", stderr)
	}
}

func TestInventoryFileOrderDoesNotMatter(t *testing.T) {
	bin := buildCLI(t)
	dir := t.TempDir()
	jsonOut := filepath.Join(dir, "inv.json")
	conf := filepath.Join(fixtures, "sample2.txt")

	// Natural order: file before the flags.
	stdout, _, code := run(t, bin, "inventory", conf, "--json", jsonOut)
	if code != 0 {
		t.Fatalf("code = %d", code)
	}
	if !strings.Contains(stdout, "SRX INVENTORY") {
		t.Errorf("expected text report on stdout")
	}
	if _, err := os.Stat(jsonOut); err != nil {
		t.Fatalf("%s not created: %v", jsonOut, err)
	}

	// Reverse order: flags before the file — should also work.
	jsonOut2 := filepath.Join(dir, "inv2.json")
	_, _, code2 := run(t, bin, "inventory", "--json", jsonOut2, conf)
	if code2 != 0 {
		t.Fatalf("code (flags before file) = %d", code2)
	}
	if _, err := os.Stat(jsonOut2); err != nil {
		t.Fatalf("%s not created: %v", jsonOut2, err)
	}
}

func TestAuditMinSeverityFilters(t *testing.T) {
	bin := buildCLI(t)
	conf := filepath.Join(fixtures, "sample-show-config.txt")

	stdoutAll, _, code := run(t, bin, "audit", conf)
	if code != 0 {
		t.Fatalf("code = %d", code)
	}
	stdoutHigh, _, code2 := run(t, bin, "audit", conf, "--min-severity", "HIGH")
	if code2 != 0 {
		t.Fatalf("code = %d", code2)
	}
	if len(stdoutHigh) >= len(stdoutAll) {
		t.Fatalf("--min-severity HIGH should produce a shorter report")
	}
	if !strings.Contains(stdoutHigh, "CRITICAL") {
		t.Errorf("CRITICAL should still be present with --min-severity HIGH")
	}
	if strings.Contains(stdoutHigh, "[LOW]") {
		t.Errorf("no LOW finding should appear with --min-severity HIGH")
	}
}

func TestAuditAllOutputFiles(t *testing.T) {
	bin := buildCLI(t)
	dir := t.TempDir()
	conf := filepath.Join(fixtures, "sample-show-config.txt")
	jsonOut := filepath.Join(dir, "a.json")
	xlsxOut := filepath.Join(dir, "a.xlsx")
	fixOut := filepath.Join(dir, "a.set")

	_, stderr, code := run(t, bin, "audit", conf, "--json", jsonOut, "--xlsx", xlsxOut, "--fix", fixOut)
	if code != 0 {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	for _, f := range []string{jsonOut, xlsxOut, fixOut} {
		info, err := os.Stat(f)
		if err != nil {
			t.Errorf("%s not created: %v", f, err)
			continue
		}
		if info.Size() == 0 {
			t.Errorf("%s is empty", f)
		}
	}
}

func TestRenameSuggestThenApply(t *testing.T) {
	bin := buildCLI(t)
	dir := t.TempDir()
	conf := filepath.Join(fixtures, "sample2.txt")
	csvOut := filepath.Join(dir, "plan.csv")

	_, _, code := run(t, bin, "rename-suggest", conf, "--csv", csvOut)
	if code != 0 {
		t.Fatalf("suggest: code = %d", code)
	}
	data, err := os.ReadFile(csvOut)
	if err != nil {
		t.Fatalf("reading the CSV: %v", err)
	}
	if !strings.Contains(string(data), "10.10.10.50") {
		t.Fatalf("unexpected CSV: %s", data)
	}

	filled := strings.Replace(string(data), "trust-host-50,",
		"trust-host-50,web-corp-01", 1)
	// Fixes the header line, which also contains "trust-host-50," as a
	// column suffix: Replace(...,1) only replaces the first occurrence,
	// which is the data line, not the header (the header doesn't contain
	// this substring).
	if err := os.WriteFile(csvOut, []byte(filled), 0o644); err != nil {
		t.Fatal(err)
	}

	setOut := filepath.Join(dir, "rename.set")
	rollbackOut := filepath.Join(dir, "rollback.set")
	stdout, stderr, code2 := run(t, bin, "rename-apply", conf, "--map", csvOut, "--set", setOut, "--rollback", rollbackOut)
	if code2 != 0 {
		t.Fatalf("apply: code = %d, stdout=%s stderr=%s", code2, stdout, stderr)
	}
	setData, err := os.ReadFile(setOut)
	if err != nil {
		t.Fatalf("reading %s: %v", setOut, err)
	}
	if !strings.Contains(string(setData), "web-corp-01") {
		t.Errorf("expected commands missing: %s", setData)
	}
	if _, err := os.Stat(rollbackOut); err != nil {
		t.Errorf("rollback not created: %v", err)
	}
}

func TestCleanupEndToEnd(t *testing.T) {
	bin := buildCLI(t)
	dir := t.TempDir()
	conf := filepath.Join(fixtures, "sample2.txt")

	invOut := filepath.Join(dir, "inv.json")
	if _, _, code := run(t, bin, "inventory", conf, "--json", invOut); code != 0 {
		t.Fatalf("inventory failed")
	}

	hitFile := filepath.Join(dir, "hitcount.xml")
	hitXML := `<security-policies-hit-count-information>
<policy-hit-count>
<from-zone>trust</from-zone><to-zone>untrust</to-zone><policy-name>allow-web</policy-name>
<count>0</count><policy-action>permit</policy-action>
</policy-hit-count>
</security-policies-hit-count-information>`
	if err := os.WriteFile(hitFile, []byte(hitXML), 0o644); err != nil {
		t.Fatal(err)
	}

	setOut := filepath.Join(dir, "cleanup.set")
	_, stderr, code := run(t, bin, "cleanup", "--inventory", invOut, "--hitcount", hitFile, "--set", setOut)
	if code != 0 {
		t.Fatalf("cleanup: code = %d, stderr = %s", code, stderr)
	}
	if !strings.Contains(stderr, "candidates for removal: 1") {
		t.Errorf("expected summary missing from stderr: %s", stderr)
	}
	data, err := os.ReadFile(setOut)
	if err != nil {
		t.Fatalf("reading %s: %v", setOut, err)
	}
	if !strings.Contains(string(data), "delete security policies from-zone trust to-zone untrust policy allow-web") {
		t.Errorf("expected removal command missing: %s", data)
	}
}

func TestBadConfExitsNonZeroWithoutPanicking(t *testing.T) {
	bin := buildCLI(t)
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.txt")
	os.WriteFile(bad, []byte("this is not a configuration\n"), 0o644)

	stdout, stderr, code := run(t, bin, "audit", bad)
	if code != 1 {
		t.Fatalf("code = %d, expected 1", code)
	}
	if stdout != "" {
		t.Errorf("no report should be printed on failure: %q", stdout)
	}
	if !strings.Contains(stderr, "error") {
		t.Errorf("expected error message on stderr: %q", stderr)
	}
}

func TestMissingFileExitsCleanly(t *testing.T) {
	bin := buildCLI(t)
	_, stderr, code := run(t, bin, "audit", "/does/not/exist.txt")
	if code != 1 {
		t.Fatalf("code = %d, expected 1", code)
	}
	if !strings.Contains(stderr, "read") {
		t.Errorf("expected message missing: %q", stderr)
	}
}

func TestUnknownSubcommand(t *testing.T) {
	bin := buildCLI(t)
	_, stderr, code := run(t, bin, "frobnicate")
	if code != 2 {
		t.Fatalf("code = %d, expected 2", code)
	}
	if !strings.Contains(stderr, "unknown") {
		t.Errorf("expected message missing: %q", stderr)
	}
}
