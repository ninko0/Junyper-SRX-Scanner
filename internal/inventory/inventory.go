// Package inventory reproduces `srxtool.py inventory`: the VLAN -> zone ->
// addresses -> policies classification.
//
// Read-only and side-effect free: no command is generated here, and the
// package performs no disk writes (the report and the JSON are returned in
// memory, the XLSX is written to an io.Writer supplied by the caller).
// This is what lets task 05's HTTP layer stream a workbook with no
// temporary file.
package inventory

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/local/srxtool-go/internal/config"
	"github.com/local/srxtool-go/internal/xlsx"
)

// AddressObject: consolidated address-book object, with its reference
// count (policies + address-sets).
type AddressObject struct {
	Name       string   `json:"name"`
	Prefix     *string  `json:"prefix"`
	Book       string   `json:"book"`
	BookType   string   `json:"book_type"` // "global" | "zone"
	Zones      []string `json:"zones"`
	References int      `json:"references"`
}

// Usage: a location where an address object is referenced. Kept in full
// (not just counted) because task 04 needs it to repoint EVERY reference
// during a rename.
type Usage struct {
	Kind     string   `json:"kind"` // "policy-src" | "policy-dst" | "address-set"
	FromZone string   `json:"from_zone,omitempty"`
	ToZone   string   `json:"to_zone,omitempty"`
	Policy   string   `json:"policy,omitempty"`
	Apps     []string `json:"apps,omitempty"`
	Book     string   `json:"book,omitempty"`
	BookType string   `json:"book_type,omitempty"`
	Set      string   `json:"set,omitempty"`
}

// Result aggregates everything the inventory produces.
type Result struct {
	Model          *config.Model
	ZoneObjects    map[string][]string
	AddressObjects []AddressObject
	Usages         map[string][]Usage
}

// Build: port of build_address_index() (srxtool.py L745-797) and
// build_inventory_model() (L1227-1254).
func Build(m *config.Model) *Result {
	type key struct{ book, name string }
	objs := map[key]AddressObject{}

	for _, bn := range sortedKeys(m.GlobalBooks) {
		b := m.GlobalBooks[bn]
		for _, name := range sortedKeys(b.Addresses) {
			objs[key{bn, name}] = AddressObject{
				Name: name, Prefix: b.Addresses[name], Book: bn,
				BookType: "global", Zones: append([]string{}, b.Zones...),
			}
		}
	}
	for _, zn := range sortedKeys(m.Zones) {
		lb := m.Zones[zn].LegacyBook
		if lb == nil {
			continue
		}
		for _, name := range sortedKeys(lb.Addresses) {
			objs[key{zn, name}] = AddressObject{
				Name: name, Prefix: lb.Addresses[name], Book: zn,
				BookType: "zone", Zones: []string{zn},
			}
		}
	}

	usages := map[string][]Usage{}
	addUsage := func(name string, u Usage) {
		if name == "" || name == "any" || name == "any-ipv4" || name == "any-ipv6" {
			return
		}
		usages[name] = append(usages[name], u)
	}
	for _, p := range m.Policies {
		for _, s := range p.Source {
			addUsage(s, Usage{Kind: "policy-src", FromZone: p.FromZone,
				ToZone: p.ToZone, Policy: p.Name, Apps: p.Application})
		}
		for _, d := range p.Destination {
			addUsage(d, Usage{Kind: "policy-dst", FromZone: p.FromZone,
				ToZone: p.ToZone, Policy: p.Name, Apps: p.Application})
		}
	}
	scanSets := func(bookName string, sets map[string]config.AddressSet, bookType string) {
		for _, sn := range sortedKeys(sets) {
			for _, mem := range sets[sn].Addresses {
				// Note: unlike policies, Python doesn't exclude "any" here.
				// Behavior kept — an address-set named "any" would be
				// pathological anyway.
				usages[mem] = append(usages[mem], Usage{
					Kind: "address-set", Book: bookName, BookType: bookType, Set: sn})
			}
		}
	}
	for _, bn := range sortedKeys(m.GlobalBooks) {
		scanSets(bn, m.GlobalBooks[bn].AddressSets, "global")
	}
	for _, zn := range sortedKeys(m.Zones) {
		if lb := m.Zones[zn].LegacyBook; lb != nil {
			scanSets(zn, lb.AddressSets, "zone")
		}
	}

	zoneObjects := map[string][]string{}
	for zn := range m.Zones {
		zoneObjects[zn] = []string{}
	}
	list := make([]AddressObject, 0, len(objs))
	for _, o := range objs {
		o.References = len(usages[o.Name])
		list = append(list, o)
		for _, zn := range o.Zones {
			zoneObjects[zn] = append(zoneObjects[zn], o.Name)
		}
	}
	// Deterministic order: global books first (like Python's insertion
	// order), then by book and by name.
	sort.Slice(list, func(i, j int) bool {
		a, b := list[i], list[j]
		if (a.BookType == "global") != (b.BookType == "global") {
			return a.BookType == "global"
		}
		if a.Book != b.Book {
			return a.Book < b.Book
		}
		return a.Name < b.Name
	})
	for zn := range zoneObjects {
		sort.Strings(zoneObjects[zn])
	}

	return &Result{Model: m, ZoneObjects: zoneObjects, AddressObjects: list, Usages: usages}
}

// ApplicationObject: a custom application definition (protocol/port),
// flattened for the pivot JSON. Only what the configuration itself
// declares — Junos's predefined applications (junos-https, junos-ssh...)
// have no `applications { application ... }` block to read (they're built
// into the OS), so they never appear here; the consumer (mcd-elkbased)
// handles those separately via a small well-known table.
//
// A term-based, multi-service application (config.Application.Terms) is
// flattened here into the union of every term's protocol/port values —
// this loses the term-level pairing (which protocol goes with which port,
// for an application with more than one term of differing protocols),
// which is an accepted simplification: the consumer only needs "was any
// port this application could mean observed", not a strict per-term
// match.
type ApplicationObject struct {
	Name            string   `json:"name"`
	Protocol        []string `json:"protocol"`
	DestinationPort []string `json:"destination_port"`
}

// ApplicationSetObject: an application-set's member list, exported as-is
// (not expanded) — a member may itself be another application-set;
// recursive expansion is left to the consumer, same as address-sets are
// today.
type ApplicationSetObject struct {
	Name         string   `json:"name"`
	Applications []string `json:"applications"`
}

func buildApplicationObjects(m *config.Model) []ApplicationObject {
	out := make([]ApplicationObject, 0, len(m.Applications))
	for _, name := range sortedKeys(m.Applications) {
		a := m.Applications[name]
		protocol := append([]string{}, a.Protocol...)
		port := append([]string{}, a.DestinationPort...)
		for _, t := range a.Terms {
			protocol = append(protocol, t.Protocol...)
			port = append(port, t.DestinationPort...)
		}
		out = append(out, ApplicationObject{
			Name:            name,
			Protocol:        dedupStrings(protocol),
			DestinationPort: dedupStrings(port),
		})
	}
	return out
}

func buildApplicationSetObjects(m *config.Model) []ApplicationSetObject {
	out := make([]ApplicationSetObject, 0, len(m.ApplicationSets))
	for _, name := range sortedKeys(m.ApplicationSets) {
		out = append(out, ApplicationSetObject{
			Name:         name,
			Applications: m.ApplicationSets[name].Applications,
		})
	}
	return out
}

func dedupStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// jsonOut is the exact projection of build_inventory_model()'s `out` dict,
// extended with application_objects/application_sets (see task: real-port
// resolution for the "which port/destination was never used on rule X"
// mcd-elkbased report — the address_objects precedent this follows).
// Zones are deliberately reduced to inventory fields here: the audit
// fields (system_services, protocols, screen, public) carried by
// config.Model.Zone have no business being in `inv.json` and would make it
// diverge from the Python golden.
type jsonOut struct {
	SourceFormat    string                  `json:"source_format"`
	Warnings        []string                `json:"warnings"`
	VLANs           map[string]config.VLAN  `json:"vlans"`
	Zones           map[string]jsonZone     `json:"zones"`
	Policies        []jsonPolicy            `json:"policies"`
	AddressObj      []AddressObject         `json:"address_objects"`
	ApplicationObj  []ApplicationObject      `json:"application_objects"`
	ApplicationSets []ApplicationSetObject   `json:"application_sets"`
}

type jsonZone struct {
	Interfaces   []string            `json:"interfaces"`
	LegacyBook   *config.AddressBook `json:"legacy_book"`
	VLANs        []string            `json:"vlans"`
	PoliciesFrom []string            `json:"policies_from"`
	PoliciesTo   []string            `json:"policies_to"`
}

type jsonPolicy struct {
	FromZone    string   `json:"from_zone"`
	ToZone      string   `json:"to_zone"`
	Name        string   `json:"name"`
	Source      []string `json:"source"`
	Destination []string `json:"destination"`
	Application []string `json:"application"`
	Action      string   `json:"action"`
	Flags       []string `json:"flags"`
}

// JSON produces the classification in the format consumed by task 04
// (cleanup) and by the frontend.
func (r *Result) JSON() ([]byte, error) {
	out := jsonOut{
		SourceFormat:    r.Model.SourceFormat,
		Warnings:        r.Model.Warnings,
		VLANs:           r.Model.VLANs,
		Zones:           map[string]jsonZone{},
		Policies:        make([]jsonPolicy, 0, len(r.Model.Policies)),
		AddressObj:      r.AddressObjects,
		ApplicationObj:  buildApplicationObjects(r.Model),
		ApplicationSets: buildApplicationSetObjects(r.Model),
	}
	for zn, z := range r.Model.Zones {
		out.Zones[zn] = jsonZone{
			Interfaces:   z.Interfaces,
			LegacyBook:   z.LegacyBook,
			VLANs:        z.VLANs,
			PoliciesFrom: z.PoliciesFrom,
			PoliciesTo:   z.PoliciesTo,
		}
	}
	for _, p := range r.Model.Policies {
		out.Policies = append(out.Policies, jsonPolicy{
			FromZone: p.FromZone, ToZone: p.ToZone, Name: p.Name,
			Source: p.Source, Destination: p.Destination,
			Application: p.Application, Action: p.Action, Flags: p.Flags,
		})
	}
	return json.MarshalIndent(out, "", "  ")
}

// ReportText: port of build_inventory_report_text() (srxtool.py
// L1257-1302). This is human-reviewed business content, not a
// presentation detail.
func (r *Result) ReportText() string {
	m := r.Model
	var lines []string
	sep := strings.Repeat("=", 70)
	lines = append(lines, sep,
		"SRX INVENTORY — VLAN / ZONE / ADDRESSES / POLICIES",
		sep,
		fmt.Sprintf("Detected source format: %s", orQuestion(m.SourceFormat)))
	if len(m.Warnings) > 0 {
		lines = append(lines, "",
			fmt.Sprintf("⚠ %d READ WARNING(S) — the inventory may be incomplete:",
				len(m.Warnings)))
		for _, w := range m.Warnings {
			lines = append(lines, "    - "+w)
		}
	}
	lines = append(lines, "")

	for _, zn := range sortedKeys(m.Zones) {
		z := m.Zones[zn]
		lines = append(lines, "", "ZONE  "+zn,
			"  interfaces: "+orText(strings.Join(z.Interfaces, ", "), "(none)"))
		if len(z.VLANs) > 0 {
			lines = append(lines, "  VLANs:")
			for _, vn := range z.VLANs {
				v := m.VLANs[vn]
				lines = append(lines, fmt.Sprintf("    - %s (id %s, %s) subnet %s | ports %s",
					vn, pyStr(v.VlanID), pyStr(v.L3Interface),
					orText(strings.Join(v.L3Addresses, ", "), "-"),
					orText(strings.Join(v.Members, ", "), "-")))
			}
		} else {
			lines = append(lines, "  VLANs: (no L3 VLAN attached to this zone)")
		}
		objs := r.ZoneObjects[zn]
		lines = append(lines, fmt.Sprintf("  address objects (%d): %s",
			len(objs), orText(strings.Join(objs, ", "), "(none)")))
		lines = append(lines, fmt.Sprintf("  policies (source): %d", len(z.PoliciesFrom)))
		for _, x := range z.PoliciesFrom {
			lines = append(lines, "      -> "+x)
		}
		lines = append(lines, fmt.Sprintf("  policies (destination): %d", len(z.PoliciesTo)))
		for _, x := range z.PoliciesTo {
			lines = append(lines, "      <- "+x)
		}
	}

	// Orphan VLANs: an explicit business signal — a VLAN with no L3 zone
	// is almost always a conf error (or a leftover).
	var orphan []string
	for _, vn := range sortedKeys(m.VLANs) {
		if m.VLANs[vn].Zone == nil {
			orphan = append(orphan, vn)
		}
	}
	if len(orphan) > 0 {
		lines = append(lines, "", "VLANs without an L3 zone (to check): "+strings.Join(orphan, ", "))
	}

	return strings.Join(lines, "\n")
}

// ExportXLSX: port of export_inventory_xlsx() (srxtool.py L1156-1220).
func (r *Result) ExportXLSX(w io.Writer) error {
	m := r.Model
	wb := xlsx.New()

	vlanRows := make([][]xlsx.Cell, 0, len(m.VLANs))
	for _, vn := range sortedKeys(m.VLANs) {
		v := m.VLANs[vn]
		zone, status, style := "", "NO L3 ZONE", xlsx.StyleOrphan
		if v.Zone != nil {
			zone, status, style = *v.Zone, "OK", xlsx.StyleOK
		}
		row := []xlsx.Cell{
			xlsx.Text(vn), xlsx.Text(ptrOr(v.VlanID)), xlsx.Text(ptrOr(v.L3Interface)),
			xlsx.Text(zone),
			xlsx.Text(orText(strings.Join(v.L3Addresses, ", "), "-")),
			xlsx.Text(orText(strings.Join(v.Members, ", "), "-")),
			xlsx.Text(status),
		}
		vlanRows = append(vlanRows, styleRow(row, style))
	}
	wb.AddSheet("VLANs",
		[]string{"VLAN", "VLAN ID", "L3 Interface", "Zone", "Subnet(s)", "Members (ports)", "Status"},
		vlanRows, 14, 10, 16, 14, 30, 30, 16)

	zoneRows := make([][]xlsx.Cell, 0, len(m.Zones))
	for _, zn := range sortedKeys(m.Zones) {
		z := m.Zones[zn]
		zoneRows = append(zoneRows, []xlsx.Cell{
			xlsx.Text(zn),
			xlsx.Text(orText(strings.Join(z.Interfaces, ", "), "-")),
			xlsx.Text(orText(strings.Join(z.VLANs, ", "), "-")),
			xlsx.Text(orText(strings.Join(r.ZoneObjects[zn], ", "), "-")),
			xlsx.Num(len(z.PoliciesFrom)),
			xlsx.Num(len(z.PoliciesTo)),
		})
	}
	wb.AddSheet("Zones",
		[]string{"Zone", "Interfaces", "VLANs", "Address objects", "Policies (source)", "Policies (destination)"},
		zoneRows, 16, 30, 20, 40, 18, 22)

	polRows := make([][]xlsx.Cell, 0, len(m.Policies))
	for _, p := range m.Policies {
		srcAny := contains(p.Source, "any") || contains(p.Source, "any-ipv4")
		dstAny := contains(p.Destination, "any") || contains(p.Destination, "any-ipv4")
		appAny := contains(p.Application, "any")
		style := xlsx.StyleNone
		switch {
		case p.Action == "permit" && srcAny && dstAny && appAny:
			style = xlsx.StyleCritical
		case p.Action == "permit" && appAny:
			style = xlsx.StyleHigh
		case p.Action == "permit" && srcAny && dstAny:
			style = xlsx.StyleMedium
		}
		row := []xlsx.Cell{
			xlsx.Text(p.FromZone), xlsx.Text(p.ToZone), xlsx.Text(p.Name),
			xlsx.Text(strings.Join(p.Source, ", ")),
			xlsx.Text(strings.Join(p.Destination, ", ")),
			xlsx.Text(strings.Join(p.Application, ", ")),
			xlsx.Text(p.Action),
			xlsx.Text(orText(strings.Join(p.Flags, ", "), "-")),
		}
		polRows = append(polRows, styleRow(row, style))
	}
	wb.AddSheet("Policies",
		[]string{"From-zone", "To-zone", "Policy", "Source", "Destination", "Application", "Action", "Flags"},
		polRows, 14, 14, 22, 30, 30, 20, 10, 20)

	addrRows := make([][]xlsx.Cell, 0, len(r.AddressObjects))
	for _, a := range r.AddressObjects {
		style := xlsx.StyleNone
		if a.References == 0 {
			// An object that's never referenced is a cleanup candidate:
			// same color code as orphan VLANs.
			style = xlsx.StyleOrphan
		}
		row := []xlsx.Cell{
			xlsx.Text(a.Name), xlsx.Text(ptrOr(a.Prefix)), xlsx.Text(a.Book),
			xlsx.Text(a.BookType), xlsx.Text(strings.Join(a.Zones, ", ")),
			xlsx.Num(a.References),
		}
		addrRows = append(addrRows, styleRow(row, style))
	}
	wb.AddSheet("Address objects",
		[]string{"Name", "Prefix/value", "Book", "Book type", "Zones", "References"},
		addrRows, 24, 22, 18, 12, 24, 12)

	return wb.Write(w)
}

func styleRow(row []xlsx.Cell, s xlsx.Style) []xlsx.Cell {
	if s == xlsx.StyleNone {
		return row
	}
	for i := range row {
		row[i].Style = s
	}
	return row
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func contains(ss []string, v string) bool {
	for _, s := range ss {
		if s == v {
			return true
		}
	}
	return false
}

func orText(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func orQuestion(s string) string {
	if s == "" {
		return "?"
	}
	return s
}

func ptrOr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// pyStr reproduces Python's interpolation of an absent value: `None`.
func pyStr(p *string) string {
	if p == nil {
		return "None"
	}
	return *p
}
