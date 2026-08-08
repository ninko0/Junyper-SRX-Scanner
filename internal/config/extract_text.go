package config

// parseConfigText merges parse_config_text() (srxtool.py L562-677) and
// parse_text() (srxaudit.py L226-310) into a single extraction: both
// Python functions walked the same tree to derive two partially
// redundant models.
func parseConfigText(text string) *Model {
	root, warnings, fmtName := parseTextAuto(text)

	m := &Model{
		Units:           map[string]Unit{},
		VLANs:           map[string]VLAN{},
		Zones:           map[string]Zone{},
		GlobalBooks:     map[string]GlobalBook{},
		Applications:    map[string]Application{},
		ApplicationSets: map[string]ApplicationSet{},
		Warnings:        warnings,
		SourceFormat:    fmtName,
	}

	system := root.CChild("system")
	snmp := root.CChild("snmp")
	security := root.CChild("security")
	interfacesEl := root.CChild("interfaces")
	m.System, m.SNMP, m.Security, m.Interfaces = system, snmp, security, interfacesEl

	// --- applications ---------------------------------------------------
	//
	// Top-level `applications { ... }` stanza — a sibling of `security`,
	// not nested under it. Only what the configuration actually declares
	// (custom applications and application-sets); Junos's predefined
	// applications (junos-https, junos-ssh...) are wired into the OS, not
	// declared here — see mcd-elkbased's well-known-application table for
	// how the consumer handles those.
	if appsEl := root.CChild("applications"); appsEl != nil {
		for _, ac := range appsEl.CChildren("application") {
			if len(ac.Header) == 0 {
				continue
			}
			name := ac.Header[0]
			app := Application{
				Protocol:        ac.Node.CValues("protocol"),
				DestinationPort: ac.Node.CValues("destination-port"),
			}
			for _, tc := range ac.Node.CChildren("term") {
				if len(tc.Header) == 0 {
					continue
				}
				app.Terms = append(app.Terms, ApplicationTerm{
					Name:            tc.Header[0],
					Protocol:        tc.Node.CValues("protocol"),
					DestinationPort: tc.Node.CValues("destination-port"),
				})
			}
			m.Applications[name] = app
		}
		for _, sc := range appsEl.CChildren("application-set") {
			if len(sc.Header) == 0 {
				continue
			}
			m.ApplicationSets[sc.Header[0]] = ApplicationSet{
				Applications: orEmpty(sc.Node.CValues("application")),
			}
		}
	}

	// --- interfaces / units -------------------------------------------------
	if interfacesEl != nil {
		for _, ic := range interfacesEl.Children {
			if len(ic.Header) == 0 {
				continue
			}
			iname := ic.Header[0]
			for _, uc := range ic.Node.CChildren("unit") {
				if len(uc.Header) == 0 {
					continue
				}
				uname := uc.Header[0]
				var inetAddrs, vlanMembers []string
				// "family inet { ... }" is ONE block with header
				// ["family","inet"], not a "family" block nesting "inet".
				for _, fc := range uc.Node.CChildren("family") {
					if len(fc.Header) == 0 {
						continue
					}
					switch fc.Header[0] {
					case "inet":
						inetAddrs = append(inetAddrs, fc.Node.CValues("address")...)
					case "ethernet-switching":
						if vlan := fc.Node.CChild("vlan"); vlan != nil {
							vlanMembers = append(vlanMembers, vlan.CValues("members")...)
						}
					}
				}
				m.Units[iname+"."+uname] = Unit{
					Interface:   iname,
					Unit:        uname,
					Inet:        orEmpty(inetAddrs),
					VLANMembers: orEmpty(vlanMembers),
				}
			}
		}
	}

	// --- VLANs ---------------------------------------------------------------
	if vlansEl := root.CChild("vlans"); vlansEl != nil {
		for _, vc := range vlansEl.Children {
			if len(vc.Header) == 0 {
				continue
			}
			m.VLANs[vc.Header[0]] = VLAN{
				VlanID:      leafPtr(vc.Node, "vlan-id"),
				L3Interface: leafPtr(vc.Node, "l3-interface"),
				Members:     []string{},
			}
		}
	}
	attachVLANMembers(m)

	// --- screens ---------------------------------------------------------------
	if screenRoot := security.CChild("screen"); screenRoot != nil {
		for _, ic := range screenRoot.CChildren("ids-option") {
			if len(ic.Header) > 0 {
				m.Screens = append(m.Screens, ic.Header[0])
			}
		}
	}

	// --- zones -----------------------------------------------------------------
	if zel := security.CChild("zones"); zel != nil {
		for _, zc := range zel.CChildren("security-zone") {
			if len(zc.Header) == 0 || zc.Header[0] == "" {
				continue
			}
			zn := zc.Header[0]
			z := zc.Node
			ifaces := z.CChild("interfaces").CBareNames()
			var book *AddressBook
			if ab := z.CChild("address-book"); ab != nil {
				b := parseAddressBookText(ab)
				book = &b
			}
			hit := z.CChild("host-inbound-traffic")
			m.Zones[zn] = Zone{
				Interfaces:     orEmpty(ifaces),
				LegacyBook:     book,
				SystemServices: orEmpty(hit.CValues("system-services")),
				Protocols:      orEmpty(hit.CValues("protocols")),
				Screen:         leafPtr(z, "screen"),
			}
		}
	}

	// --- global address books -------------------------------------------------
	//
	// DELIBERATE DIVERGENCE #1 (to report in MD 09).
	//
	// Junos renders `set security address-book global address X` in the
	// nested form `address-book { global { ... } }`. Python only reads
	// the direct children of the `address-book` node: on this form —
	// which is the one a standard `show configuration` produces — it
	// records an EMPTY "global" book and silently loses every global
	// object. Verified against the reference code, not inferred.
	//
	// Consequence if the bug were reproduced: the inventory (task 02)
	// would show no global object, and worse, rename (task 04) would
	// generate a migration plan that doesn't repoint global references —
	// i.e. `set`/`delete` commands that break the device's conf. The
	// bug's cost is too high to reproduce; it's fixed here and
	// documented.
	for _, bc := range security.CChildren("address-book") {
		if len(bc.Header) > 0 {
			m.GlobalBooks[bc.Header[0]] = buildGlobalBook(bc.Node)
			continue
		}
		// `address-book { ... }` with no name in the header: either the
		// book carries the objects directly (Python behavior kept), or
		// it contains named sub-blocks (`global { ... }`).
		if bc.Node.CHas("address") || bc.Node.CHas("address-set") {
			m.GlobalBooks["global"] = buildGlobalBook(bc.Node)
			continue
		}
		named := false
		for _, sub := range bc.Node.Children {
			if len(sub.Header) == 0 {
				continue
			}
			named = true
			m.GlobalBooks[sub.Header[0]] = buildGlobalBook(sub.Node)
		}
		if !named {
			m.GlobalBooks["global"] = buildGlobalBook(bc.Node)
		}
	}

	// --- policies ----------------------------------------------------------
	if polRoot := security.CChild("policies"); polRoot != nil {
		for _, pb := range polRoot.Children {
			h := pb.Header
			if !(len(h) >= 4 && h[0] == "from-zone" && h[2] == "to-zone") {
				continue
			}
			fz, tz := h[1], h[3]
			for _, pc := range pb.Node.CChildren("policy") {
				pn := ""
				if len(pc.Header) > 0 {
					pn = pc.Header[0]
				}
				match := pc.Node.CChild("match")
				p := Policy{
					FromZone:    fz,
					ToZone:      tz,
					Name:        pn,
					Source:      orAny(match.CValues("source-address")),
					Destination: orAny(match.CValues("destination-address")),
					Application: orAny(match.CValues("application")),
					Action:      "permit",
					Flags:       []string{},
					Logs:        []string{},
				}
				if then := pc.Node.CChild("then"); then != nil {
					action := ""
					for _, l := range then.Leaves {
						switch l.Key {
						case "permit", "deny", "reject":
							action = l.Key
						case "log":
							// srxtool: "log " + first value only.
							first := ""
							if len(l.Vals) > 0 {
								first = l.Vals[0]
							}
							p.Flags = append(p.Flags, "log "+first)
							// srxaudit: every value.
							p.Logs = append(p.Logs, l.Vals...)
						case "count":
							p.Flags = append(p.Flags, "count")
						}
					}
					for _, tc := range then.Children {
						if len(tc.Header) == 0 {
							continue
						}
						switch tc.Header[0] {
						case "permit", "deny", "reject":
							action = tc.Header[0]
						case "log":
							for _, lg := range tc.Node.CBareNames() {
								p.Flags = append(p.Flags, "log "+lg)
								p.Logs = append(p.Logs, lg)
							}
						case "count":
							p.Flags = append(p.Flags, "count")
						}
					}
					if action != "" {
						p.Action = action
					}
				}
				m.Policies = append(m.Policies, p)
			}
		}
	}

	computePublicZones(m)
	finalizeModel(m)
	return m
}

// parseAddressBookText: port of parse_address_book_body_text()
// (srxtool.py L529-559).
func parseAddressBookText(ab *Node) AddressBook {
	book := AddressBook{
		Addresses:   map[string]*string{},
		AddressSets: map[string]AddressSet{},
	}
	if ab == nil {
		return book
	}
	for _, ac := range ab.CChildren("address") {
		if len(ac.Header) == 0 {
			continue
		}
		an := ac.Header[0]
		var pfx *string
		if v, ok := ac.Node.CLeaf("ip-prefix"); ok {
			pfx = strPtr(v)
		}
		if pfx == nil {
			if dn := ac.Node.CChild("dns-name"); dn != nil {
				v, _ := dn.CBareValue()
				pfx = strPtr("dns:" + v)
			}
			if rng := ac.Node.CChild("range-address"); rng != nil {
				v, _ := rng.CBareValue()
				pfx = strPtr("range:" + v)
			}
		}
		if pfx == nil {
			// 'display set' form: "address NAME PREFIX"
			// -> address { NAME { PREFIX; } }
			if v, ok := ac.Node.CBareValue(); ok {
				pfx = strPtr(v)
			}
		}
		book.Addresses[an] = pfx
	}
	// direct leaf form: "address NAME PREFIX;"
	for _, l := range ab.Leaves {
		if l.Key == "address" && len(l.Vals) >= 2 {
			book.Addresses[l.Vals[0]] = strPtr(l.Vals[1])
		}
	}
	for _, sc := range ab.CChildren("address-set") {
		if len(sc.Header) == 0 {
			continue
		}
		book.AddressSets[sc.Header[0]] = AddressSet{
			Addresses:   orEmpty(sc.Node.CValues("address")),
			AddressSets: orEmpty(sc.Node.CValues("address-set")),
		}
	}
	return book
}

// --- helpers shared by both extraction paths -------------------------------

func attachVLANMembers(m *Model) {
	for _, full := range sortedKeys(m.Units) {
		u := m.Units[full]
		for _, vm := range u.VLANMembers {
			if v, ok := m.VLANs[vm]; ok {
				v.Members = append(v.Members, full)
				m.VLANs[vm] = v
			}
		}
	}
}

// computePublicZones: port of
// `public = any(any(not is_private(a) for a in units.get(i, [])) for i in ifaces)`
func computePublicZones(m *Model) {
	for zn := range m.Zones {
		z := m.Zones[zn]
		public := false
		for _, i := range z.Interfaces {
			u, ok := m.Units[i]
			if !ok {
				continue
			}
			for _, a := range u.Inet {
				if !isPrivate(a) {
					public = true
					break
				}
			}
			if public {
				break
			}
		}
		z.Public = public
		m.Zones[zn] = z
	}
}

func leafPtr(n *Node, key string) *string {
	if v, ok := n.CLeaf(key); ok {
		return strPtr(v)
	}
	return nil
}

func orEmpty(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

// orAny reproduces `src or ["any"]`: an empty list means "any".
func orAny(in []string) []string {
	if len(in) == 0 {
		return []string{"any"}
	}
	return in
}

// buildGlobalBook assembles a global book (objects + zone attachments).
func buildGlobalBook(n *Node) GlobalBook {
	b := parseAddressBookText(n)
	var zlist []string
	if attach := n.CChild("attach"); attach != nil {
		zlist = attach.CValues("zone")
	}
	return GlobalBook{
		Addresses:   b.Addresses,
		AddressSets: b.AddressSets,
		Zones:       orEmpty(zlist),
	}
}
