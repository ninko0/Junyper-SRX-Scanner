package rules

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/local/srxtool-go/internal/config"
	"github.com/local/srxtool-go/internal/inventory"
)

const richFixture = `system {
    services {
        ssh {
            root-login deny;
        }
    }
}
security {
    zones {
        security-zone trust {
            interfaces {
                vlan.10;
            }
            address-book {
                address 10.10.10.50 10.10.10.50/32;
                address-set corp-servers {
                    address 10.10.10.50;
                }
            }
        }
        security-zone untrust {
            interfaces {
                ge-0/0/0.0;
            }
        }
    }
    policies {
        from-zone trust to-zone untrust {
            policy allow-web {
                match {
                    source-address corp-servers;
                    destination-address any;
                    application junos-https;
                }
                then {
                    permit;
                    log {
                        session-close;
                    }
                }
            }
        }
        from-zone untrust to-zone trust {
            policy any-any {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                then {
                    permit;
                }
            }
        }
    }
}
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 203.0.113.1/30;
            }
        }
    }
    vlan {
        unit 10 {
            family inet {
                address 10.10.10.1/24;
            }
        }
    }
}
vlans {
    VLAN10 {
        vlan-id 10;
        l3-interface vlan.10;
    }
}
`

const hitcountXML = `<security-policies-hit-count-information>
<policy-hit-count>
<from-zone>trust</from-zone>
<to-zone>untrust</to-zone>
<policy-name>allow-web</policy-name>
<count>0</count>
<policy-action>permit</policy-action>
</policy-hit-count>
<policy-hit-count>
<from-zone>untrust</from-zone>
<to-zone>trust</to-zone>
<policy-name>any-any</policy-name>
<count>0</count>
<policy-action>permit</policy-action>
</policy-hit-count>
</security-policies-hit-count-information>
`

// wantRenameSetCmds: structurally matches the EXACT output obtained by
// running srxtool.py (rename, --from-map phase) on richFixture with the
// mapping {"trust"/"10.10.10.50": "web-corp-01"} — banner/comment text
// translated to English per backlog item 3 (English pass), so this is no
// longer a byte-for-byte match against the French Python reference, only a
// structural/logic one (same commands, same order, same rollback). Fixed
// here as an inline golden (the fixture is too small to justify a separate
// file).
var wantRenameSetCmds = []string{
	"# --- rename IP-named objects -> service name ---",
	"# Load under 'configure private' then 'commit check'.",
	"",
	"# 10.10.10.50  ->  web-corp-01   (10.10.10.50/32, 1 reference(s))",
	"set security zones security-zone trust address-book address web-corp-01 10.10.10.50/32",
	"set security zones security-zone trust address-book address-set corp-servers address web-corp-01",
	"delete security zones security-zone trust address-book address-set corp-servers address 10.10.10.50",
	"delete security zones security-zone trust address-book address 10.10.10.50",
}

func TestApplyRenameMapMatchesPython(t *testing.T) {
	m, err := config.Parse([]byte(richFixture), config.Options{})
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	inv := inventory.Build(m)
	cands := DetectIPNamedObjects(inv, m)
	if len(cands) != 1 || cands[0].OldName != "10.10.10.50" {
		t.Fatalf("unexpected candidates: %+v", cands)
	}
	if cands[0].ZoneHint != "trust" {
		t.Errorf("zone_hint = %q, expected trust", cands[0].ZoneHint)
	}

	mapping := map[RenameMapKey]string{{Book: "trust", OldName: "10.10.10.50"}: "web-corp-01"}
	setCmds, rollback, err := ApplyRenameMap(cands, mapping)
	if err != nil {
		t.Fatalf("ApplyRenameMap: %v", err)
	}
	if got, want := strings.Join(setCmds, "\n"), strings.Join(wantRenameSetCmds, "\n"); got != want {
		t.Errorf("setCmds mismatch:\n--- go ---\n%s\n--- want ---\n%s", got, want)
	}
	joined := strings.Join(rollback, "\n")
	for _, must := range []string{
		"set security zones security-zone trust address-book address 10.10.10.50 10.10.10.50/32",
		"set security zones security-zone trust address-book address-set corp-servers address 10.10.10.50",
		"delete security zones security-zone trust address-book address-set corp-servers address web-corp-01",
		"delete security zones security-zone trust address-book address web-corp-01",
	} {
		if !strings.Contains(joined, must) {
			t.Errorf("rollback: missing line %q\n--- rollback ---\n%s", must, joined)
		}
	}
}

func TestApplyRenameMapUnknownCandidateIgnored(t *testing.T) {
	setCmds, _, err := ApplyRenameMap(nil, map[RenameMapKey]string{
		{Book: "trust", OldName: "ghost"}: "new-name",
	})
	if err != nil {
		t.Fatalf("ApplyRenameMap: %v", err)
	}
	found := false
	for _, l := range setCmds {
		if strings.Contains(l, "[ignored] trust/ghost not found") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected ignore comment missing from: %v", setCmds)
	}
}

// TestCleanupMatchesPython reproduces the scenario manually verified
// against srxtool.cmd_cleanup(): two policies at hit-count 0, both permit
// -> both candidates for removal, with a rebuilt rollback.
func TestCleanupMatchesPython(t *testing.T) {
	m, err := config.Parse([]byte(richFixture), config.Options{})
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	inv := inventory.Build(m)
	b, err := inv.JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	var out struct {
		Policies []CleanupPolicy `json:"policies"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	hits, err := ParseHitcount(strings.NewReader(hitcountXML))
	if err != nil {
		t.Fatalf("ParseHitcount: %v", err)
	}
	if len(hits) != 2 {
		t.Fatalf("expected 2 hitcount entries, got %d", len(hits))
	}

	res, err := Cleanup(out.Policies, hits, CleanupOptions{})
	if err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if len(res.Candidates) != 2 {
		t.Fatalf("expected 2 candidates, got %d: %v", len(res.Candidates), res.Candidates)
	}
	if len(res.KeptDeny) != 0 || len(res.Unknown) != 0 || len(res.Excluded) != 0 {
		t.Errorf("unexpected categories populated: %+v", res)
	}

	wantDel1 := "delete security policies from-zone trust to-zone untrust policy allow-web"
	wantDel2 := "delete security policies from-zone untrust to-zone trust policy any-any"
	joined := strings.Join(res.SetCommands, "\n")
	if !strings.Contains(joined, wantDel1) || !strings.Contains(joined, wantDel2) {
		t.Errorf("missing deletion commands:\n%s", joined)
	}

	rb := strings.Join(res.Rollback, "\n")
	for _, must := range []string{
		"set security policies from-zone trust to-zone untrust policy allow-web match source-address corp-servers",
		"set security policies from-zone trust to-zone untrust policy allow-web then log session-close",
		"set security policies from-zone untrust to-zone trust policy any-any then permit",
	} {
		if !strings.Contains(rb, must) {
			t.Errorf("rollback: missing line %q", must)
		}
	}
}

// TestCleanupDenyKeptByDefault: a deny rule at 0 hits must be kept by
// default (IncludeDeny=false), this is task 04's explicit guard rail.
func TestCleanupDenyKeptByDefault(t *testing.T) {
	policies := []CleanupPolicy{
		{FromZone: "untrust", ToZone: "trust", Name: "deny-all", Action: "deny"},
	}
	hits := map[PolicyKey]HitInfo{
		{FromZone: "untrust", ToZone: "trust", Name: "deny-all"}: {Count: 0, Action: "deny"},
	}
	res, err := Cleanup(policies, hits, CleanupOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Candidates) != 0 || len(res.KeptDeny) != 1 {
		t.Fatalf("deny at 0 hits should be kept by default: %+v", res)
	}

	res2, err := Cleanup(policies, hits, CleanupOptions{IncludeDeny: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res2.Candidates) != 1 {
		t.Fatalf("--include-deny should force inclusion: %+v", res2)
	}
}

// TestCleanupUnknownNeverDeleted: a policy with no matching hit-count is
// listed as ignored, never removed — even if its action is permit.
func TestCleanupUnknownNeverDeleted(t *testing.T) {
	policies := []CleanupPolicy{{FromZone: "a", ToZone: "b", Name: "orphan", Action: "permit"}}
	res, err := Cleanup(policies, map[PolicyKey]HitInfo{}, CleanupOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Unknown) != 1 || len(res.Candidates) != 0 {
		t.Fatalf("policy with no hitcount should be 'unknown', not removed: %+v", res)
	}
}

// TestCleanupOnlyAndExclude checks the --only/--exclude glob patterns.
func TestCleanupOnlyAndExclude(t *testing.T) {
	policies := []CleanupPolicy{
		{FromZone: "a", ToZone: "b", Name: "old-1", Action: "permit"},
		{FromZone: "a", ToZone: "b", Name: "old-2", Action: "permit"},
		{FromZone: "a", ToZone: "b", Name: "keep-me", Action: "permit"},
	}
	hits := map[PolicyKey]HitInfo{
		{FromZone: "a", ToZone: "b", Name: "old-1"}:   {Count: 0, Action: "permit"},
		{FromZone: "a", ToZone: "b", Name: "old-2"}:   {Count: 0, Action: "permit"},
		{FromZone: "a", ToZone: "b", Name: "keep-me"}: {Count: 0, Action: "permit"},
	}
	res, err := Cleanup(policies, hits, CleanupOptions{Only: "old-*", Exclude: []string{"old-2"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Candidates) != 1 || res.Candidates[0].Name != "old-1" {
		t.Fatalf("incorrect only/exclude filter: %+v", res.Candidates)
	}
	if len(res.Excluded) != 1 || res.Excluded[0].Name != "old-2" {
		t.Fatalf("old-2 should be in Excluded: %+v", res.Excluded)
	}
	for _, p := range res.Candidates {
		if p.Name == "keep-me" {
			t.Fatal("keep-me should not pass the --only filter")
		}
	}
}

func TestParseHitcountTextFormat(t *testing.T) {
	text := `Policy: allow-web, action:permit
  From zone: trust, To zone: untrust
  Index: 4, Policy Name: allow-web, State: enabled
  Policy order: 1
  Number of policy hit: 0
Policy: any-any, action:permit
  From zone: untrust, To zone: trust
  Number of policy hit: 5
`
	hits, err := ParseHitcount(strings.NewReader(text))
	if err != nil {
		t.Fatalf("ParseHitcount: %v", err)
	}
	h1 := hits[PolicyKey{FromZone: "trust", ToZone: "untrust", Name: "allow-web"}]
	if h1.Count != 0 || h1.Action != "permit" {
		t.Errorf("allow-web: %+v", h1)
	}
	h2 := hits[PolicyKey{FromZone: "untrust", ToZone: "trust", Name: "any-any"}]
	if h2.Count != 5 {
		t.Errorf("any-any: %+v", h2)
	}
}

// hitcountEntryXML: real `show security policies hit-count | display xml`
// format (standalone, outside a cluster) — entries are
// policy-hit-count-entry, nested inside a policy-hit-count container, with
// from-zone-name/to-zone-name (not from-zone/to-zone) and
// policy-hit-count-action (not policy-action). Distinct from hitcountXML
// above, which covers the fixture's historical format (policy-hit-count =
// the entry itself), kept for regression testing.
const hitcountEntryXML = `<rpc-reply>
<policy-hit-count-information>
<policy-hit-count xmlns="http://xml.juniper.net/junos/23.4R0/junos-security-policy">
<policy-hit-count-entry junos:style="brief">
<from-zone-name>trust</from-zone-name>
<to-zone-name>untrust</to-zone-name>
<policy-name>allow-web</policy-name>
<policy-hit-count-action>Permit</policy-hit-count-action>
<count>0</count>
</policy-hit-count-entry>
<policy-hit-count-entry junos:style="brief">
<from-zone-name>untrust</from-zone-name>
<to-zone-name>trust</to-zone-name>
<policy-name>any-any</policy-name>
<policy-hit-count-action>Deny</policy-hit-count-action>
<count>5</count>
</policy-hit-count-entry>
</policy-hit-count>
</policy-hit-count-information>
</rpc-reply>
`

// hitcountClusterXML: same content as hitcountEntryXML, but wrapped as on
// an HA-clustered SRX (two more levels: rpc-reply >
// multi-routing-engine-results > multi-routing-engine-item, one per node).
// This is the case that returned 0 entries before the switch to the token
// scan (backlog item 1).
const hitcountClusterXML = `<rpc-reply>
<multi-routing-engine-results>
<multi-routing-engine-item>
<re-name>node0</re-name>
<policy-hit-count-information>
<policy-hit-count xmlns="http://xml.juniper.net/junos/23.4R0/junos-security-policy">
<policy-hit-count-entry junos:style="brief">
<from-zone-name>trust</from-zone-name>
<to-zone-name>untrust</to-zone-name>
<policy-name>allow-web</policy-name>
<policy-hit-count-action>Permit</policy-hit-count-action>
<count>0</count>
</policy-hit-count-entry>
<policy-hit-count-entry junos:style="brief">
<from-zone-name>untrust</from-zone-name>
<to-zone-name>trust</to-zone-name>
<policy-name>any-any</policy-name>
<policy-hit-count-action>Deny</policy-hit-count-action>
<count>5</count>
</policy-hit-count-entry>
</policy-hit-count>
</policy-hit-count-information>
</multi-routing-engine-item>
</multi-routing-engine-results>
<banner>{primary:node0}</banner>
</rpc-reply>
`

func TestParseHitcountEntryFormat(t *testing.T) {
	hits, err := ParseHitcount(strings.NewReader(hitcountEntryXML))
	if err != nil {
		t.Fatalf("ParseHitcount: %v", err)
	}
	if len(hits) != 2 {
		t.Fatalf("expected 2 entries, got %d: %+v", len(hits), hits)
	}
	h1 := hits[PolicyKey{FromZone: "trust", ToZone: "untrust", Name: "allow-web"}]
	if h1.Count != 0 || h1.Action != "Permit" {
		t.Errorf("allow-web: %+v", h1)
	}
	h2 := hits[PolicyKey{FromZone: "untrust", ToZone: "trust", Name: "any-any"}]
	if h2.Count != 5 || h2.Action != "Deny" {
		t.Errorf("any-any: %+v", h2)
	}
}

// TestParseHitcountClusterFormat reproduces the backlog item 1 bug: on an
// HA-clustered SRX, the multi-routing-engine-results/item encapsulation
// silently skipped policy-hit-count (0 entries, "ignored" on 100% of
// policies during cleanup) for lack of an XML struct declaring these
// levels. The token scan must find the entries regardless of depth.
func TestParseHitcountClusterFormat(t *testing.T) {
	hits, err := ParseHitcount(strings.NewReader(hitcountClusterXML))
	if err != nil {
		t.Fatalf("ParseHitcount: %v", err)
	}
	if len(hits) != 2 {
		t.Fatalf("expected 2 entries (HA cluster), got %d: %+v", len(hits), hits)
	}
	h1 := hits[PolicyKey{FromZone: "trust", ToZone: "untrust", Name: "allow-web"}]
	if h1.Count != 0 || h1.Action != "Permit" {
		t.Errorf("allow-web: %+v", h1)
	}
	h2 := hits[PolicyKey{FromZone: "untrust", ToZone: "trust", Name: "any-any"}]
	if h2.Count != 5 || h2.Action != "Deny" {
		t.Errorf("any-any: %+v", h2)
	}
}

// TestCleanupWithClusterHitcount checks the end-to-end reconciliation:
// before the fix, this scenario produced 0 candidates and every policy in
// Unknown ("Ignored (no hit-count)"), despite a real hit-count of 0.
func TestCleanupWithClusterHitcount(t *testing.T) {
	m, err := config.Parse([]byte(richFixture), config.Options{})
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	inv := inventory.Build(m)
	b, err := inv.JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	var out struct {
		Policies []CleanupPolicy `json:"policies"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	hits, err := ParseHitcount(strings.NewReader(hitcountClusterXML))
	if err != nil {
		t.Fatalf("ParseHitcount: %v", err)
	}

	res, err := Cleanup(out.Policies, hits, CleanupOptions{})
	if err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if len(res.Candidates) != 1 || res.Candidates[0].Name != "allow-web" {
		t.Fatalf("allow-web (hit-count 0) expected as the only candidate: %+v", res.Candidates)
	}
	if len(res.Unknown) != 0 {
		t.Fatalf("no policy should remain 'unknown': %+v", res.Unknown)
	}
}

func TestGlobMatch(t *testing.T) {
	cases := []struct {
		pattern, name string
		want          bool
	}{
		{"*", "anything", true},
		{"old-*", "old-1", true},
		{"old-*", "new-1", false},
		{"TEMP-*", "TEMP-obj", true},
	}
	for _, c := range cases {
		if got := globMatch(c.pattern, c.name); got != c.want {
			t.Errorf("globMatch(%q,%q) = %v, expected %v", c.pattern, c.name, got, c.want)
		}
	}
}

func TestPolicySetDeleteLinesQuoting(t *testing.T) {
	p := CleanupPolicy{
		FromZone: "trust", ToZone: "untrust", Name: "a name with spaces",
		Source: []string{"any"}, Destination: []string{"any"},
		Application: []string{"any"}, Action: "permit",
		Flags: []string{"log session-close"},
	}
	del, err := policyDeleteLine(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(del, `policy "a name with spaces"`) {
		t.Errorf("name not quoted correctly: %s", del)
	}
	lines, err := policySetLines(p)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "then log session-close") {
		t.Errorf("log flag rebuilt incorrectly: %s", joined)
	}
}

func TestPolicyUnsafeNameAborts(t *testing.T) {
	p := CleanupPolicy{FromZone: "trust", ToZone: "untrust", Name: "bad;name", Action: "permit"}
	if _, err := policyDeleteLine(p); err == nil {
		t.Fatal("a dangerous policy name should make generation fail")
	}
}
