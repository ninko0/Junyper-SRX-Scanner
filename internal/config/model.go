package config

import "fmt"

// Model is the union of the two Python models: srxtool._finalize_model()'s
// (units/vlans/zones/global_books/policies) and srxaudit.parse()'s
// (system/snmp/security/interfaces + screens + system_services/protocols/
// screen/public per zone).
//
// The two Python files parsed the same conf twice, with two slightly
// different models; that's exactly the duplication the rewrite is meant to
// remove. Here: one parser, one model, three consumers.
//
// The JSON tags reuse the Python keys exactly, so comparison against the
// golden files (`inv.json`) stays direct (task 09).
type Model struct {
	Units           map[string]Unit           `json:"units"`
	VLANs           map[string]VLAN           `json:"vlans"`
	Zones           map[string]Zone           `json:"zones"`
	GlobalBooks     map[string]GlobalBook     `json:"global_books"`
	Applications    map[string]Application    `json:"applications,omitempty"`
	ApplicationSets map[string]ApplicationSet `json:"application_sets,omitempty"`
	Policies        []Policy                  `json:"policies"`
	Screens         []string                  `json:"screens"`
	Warnings        []string                  `json:"warnings"`
	SourceFormat    string                    `json:"source_format"`

	// Raw subtrees, consumed by the audit checks (task 03). Exposed
	// behind the Tree interface so the audit no longer has to distinguish
	// XML from text (Python did this via `isinstance(system, dict)` on
	// every call).
	System     Tree `json:"-"`
	SNMP       Tree `json:"-"`
	Security   Tree `json:"-"`
	Interfaces Tree `json:"-"`
}

// Unit: a logical interface unit (`ge-0/0/0.0`).
type Unit struct {
	Interface   string   `json:"interface"`
	Unit        string   `json:"unit"`
	Inet        []string `json:"inet"`
	VLANMembers []string `json:"vlan_members"`
}

// VLAN: the pointers translate Python's `null` (value absent), to be
// distinguished from an empty string — `inv.json` relies on this
// distinction (`"l3_interface": null` for an orphan VLAN).
type VLAN struct {
	VlanID      *string  `json:"vlan_id"`
	L3Interface *string  `json:"l3_interface"`
	Members     []string `json:"members"`
	Zone        *string  `json:"zone"`
	L3Addresses []string `json:"l3_addresses"`
}

// ApplicationTerm: one `term NAME { protocol ...; destination-port ...; }`
// sub-block of a multi-service application (Junos allows an application to
// carry several terms, each its own protocol/port pair — e.g. a "APP-WEB"
// application matching both tcp/80 and tcp/443). Simple, single-term
// applications (the common case: `application NAME { protocol tcp;
// destination-port 8443; }`) have no terms — see Application.Protocol/
// DestinationPort instead.
type ApplicationTerm struct {
	Name            string   `json:"name"`
	Protocol        []string `json:"protocol"`
	DestinationPort []string `json:"destination_port"`
}

// Application: a custom `applications { application NAME { ... } }`
// definition — the piece of information Junos's *predefined* applications
// (junos-https, junos-ssh...) don't need, since those are wired into the
// OS rather than declared in the configuration (see mcd-elkbased's
// well-known-application table for the common predefined ones — this
// project only extracts what the configuration actually declares).
//
// Protocol/DestinationPort cover the simple, single-service form
// directly; Terms carries the multi-service form. A real application may
// populate either or both — a well-formed simple application populates
// Protocol/DestinationPort and leaves Terms empty; a term-based one
// leaves Protocol/DestinationPort empty and populates Terms.
type Application struct {
	Protocol        []string          `json:"protocol"`
	DestinationPort []string          `json:"destination_port"`
	Terms           []ApplicationTerm `json:"terms,omitempty"`
}

// ApplicationSet: members of an `applications { application-set NAME {
// application ...; } }` group. A member can itself name another
// application-set (nesting) — resolving that recursively is left to the
// consumer (mirrors how AddressSet's members aren't expanded here either).
type ApplicationSet struct {
	Applications []string `json:"applications"`
}

// AddressSet: members of an address-set (objects and sub-sets).
type AddressSet struct {
	Addresses   []string `json:"addresses"`
	AddressSets []string `json:"address_sets"`
}

// AddressBook: an address book (global or attached to a zone).
type AddressBook struct {
	Addresses   map[string]*string    `json:"addresses"`
	AddressSets map[string]AddressSet `json:"address_sets"`
}

// GlobalBook adds the list of attachment zones (`attach { zone X; }`).
type GlobalBook struct {
	Addresses   map[string]*string    `json:"addresses"`
	AddressSets map[string]AddressSet `json:"address_sets"`
	Zones       []string              `json:"zones"`
}

// Zone merges the inventory view and the audit view of a security-zone.
type Zone struct {
	Interfaces   []string     `json:"interfaces"`
	LegacyBook   *AddressBook `json:"legacy_book"`
	VLANs        []string     `json:"vlans"`
	PoliciesFrom []string     `json:"policies_from"`
	PoliciesTo   []string     `json:"policies_to"`

	SystemServices []string `json:"system_services"`
	Protocols      []string `json:"protocols"`
	Screen         *string  `json:"screen"`
	Public         bool     `json:"public"`
}

// Policy: Flags reproduces srxtool's `flags` field ("log session-close",
// "count"), Logs reproduces srxaudit's `logs` field (bare log names). Both
// are kept: the POL-NOLOG-* checks rely on Logs, the inventory and
// `inv.json` on Flags.
type Policy struct {
	FromZone    string   `json:"from_zone"`
	ToZone      string   `json:"to_zone"`
	Name        string   `json:"name"`
	Source      []string `json:"source"`
	Destination []string `json:"destination"`
	Application []string `json:"application"`
	Action      string   `json:"action"`
	Flags       []string `json:"flags"`
	Logs        []string `json:"logs"`
}

// finalizeModel: port of _finalize_model() (srxtool.py L680-706).
func finalizeModel(m *Model) {
	if2zone := make(map[string]string, len(m.Zones))
	for zn, z := range m.Zones {
		for _, i := range z.Interfaces {
			if2zone[i] = zn
		}
	}

	for vn, v := range m.VLANs {
		if v.L3Interface != nil {
			if zn, ok := if2zone[*v.L3Interface]; ok {
				z := zn
				v.Zone = &z
			}
			if u, ok := m.Units[*v.L3Interface]; ok {
				v.L3Addresses = u.Inet
			}
		}
		if v.L3Addresses == nil {
			v.L3Addresses = []string{}
		}
		if v.Members == nil {
			v.Members = []string{}
		}
		m.VLANs[vn] = v
	}

	for zn, z := range m.Zones {
		z.VLANs = []string{}
		for _, vn := range sortedKeys(m.VLANs) {
			if v := m.VLANs[vn]; v.Zone != nil && *v.Zone == zn {
				z.VLANs = append(z.VLANs, vn)
			}
		}
		z.PoliciesFrom = []string{}
		z.PoliciesTo = []string{}
		for _, p := range m.Policies {
			key := fmt.Sprintf("%s->%s:%s", p.FromZone, p.ToZone, p.Name)
			if p.FromZone == zn {
				z.PoliciesFrom = append(z.PoliciesFrom, key)
			}
			if p.ToZone == zn {
				z.PoliciesTo = append(z.PoliciesTo, key)
			}
		}
		if z.Interfaces == nil {
			z.Interfaces = []string{}
		}
		m.Zones[zn] = z
	}

	if m.Policies == nil {
		m.Policies = []Policy{}
	}
	if m.Warnings == nil {
		m.Warnings = []string{}
	}
	if m.Screens == nil {
		m.Screens = []string{}
	}
	if m.Applications == nil {
		m.Applications = map[string]Application{}
	}
	if m.ApplicationSets == nil {
		m.ApplicationSets = map[string]ApplicationSet{}
	}
}

// assertModelNotEmpty: port of assert_model_not_empty() (srxtool.py L709-728).
//
// Central guard rail: an audit that returns "0 findings" because it
// couldn't read anything is a clean bill of health handed out for a
// device that was never actually analyzed. We fail loudly.
func assertModelNotEmpty(m *Model, allowEmpty bool) error {
	if allowEmpty {
		return nil
	}
	if len(m.Zones) > 0 || len(m.Policies) > 0 || len(m.Units) > 0 || len(m.VLANs) > 0 {
		return nil
	}
	return &FormatError{
		Format: m.SourceFormat,
		Reason: "no usable data extracted: no zone, policy, interface, " +
			"or VLAN was read. Accepted formats: 'show configuration' (curly braces), " +
			"'show configuration | display set', 'show configuration | display xml'",
	}
}
