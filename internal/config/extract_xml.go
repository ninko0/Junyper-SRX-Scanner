package config

import "strings"

// parseConfigXMLTree fusionne parse_config_xml() (srxtool.py L412-522) et
// parse_xml() (srxaudit.py L164-223).
func parseConfigXMLTree(conf *XMLNode) *Model {
	m := &Model{
		Units:           map[string]Unit{},
		VLANs:           map[string]VLAN{},
		Zones:           map[string]Zone{},
		GlobalBooks:     map[string]GlobalBook{},
		Applications:    map[string]Application{},
		ApplicationSets: map[string]ApplicationSet{},
		Warnings:        []string{},
		SourceFormat:    "xml",
	}

	m.System = conf.kid("system")
	m.SNMP = conf.kid("snmp")
	m.Security = conf.kid("security")
	m.Interfaces = conf.kid("interfaces")

	// --- applications ---------------------------------------------------
	// Top-level <applications> element, sibling of <security> — see the
	// text-format extractor's comment for why only declared (not
	// predefined) applications are read here.
	if appsEl := conf.kid("applications"); appsEl != nil {
		for _, ac := range appsEl.kids("application") {
			name, ok := ac.txt("name")
			if !ok {
				continue
			}
			app := Application{
				Protocol:        ac.nameList("protocol"),
				DestinationPort: ac.nameList("destination-port"),
			}
			for _, tc := range ac.kids("term") {
				tname, ok := tc.txt("name")
				if !ok {
					continue
				}
				app.Terms = append(app.Terms, ApplicationTerm{
					Name:            tname,
					Protocol:        tc.nameList("protocol"),
					DestinationPort: tc.nameList("destination-port"),
				})
			}
			m.Applications[name] = app
		}
		for _, sc := range appsEl.kids("application-set") {
			sname, ok := sc.txt("name")
			if !ok {
				continue
			}
			m.ApplicationSets[sname] = ApplicationSet{
				Applications: orEmpty(sc.nameList("application")),
			}
		}
	}

	interfacesEl := conf.kid("interfaces")
	for _, itf := range interfacesEl.kids("interface") {
		iname, _ := itf.txt("name")
		for _, unit := range itf.kids("unit") {
			uname, _ := unit.txt("name")
			full := iname + "." + uname
			var inetAddrs, vlanMembers []string
			if fam := unit.kid("family"); fam != nil {
				if inet := fam.kid("inet"); inet != nil {
					for _, addr := range inet.kids("address") {
						if a, ok := addr.txt("name"); ok {
							inetAddrs = append(inetAddrs, a)
						}
					}
				}
				if eth := fam.kid("ethernet-switching"); eth != nil {
					if vlan := eth.kid("vlan"); vlan != nil {
						for _, mem := range vlan.kids("members") {
							if t := trimSpace(mem.Text); t != "" {
								vlanMembers = append(vlanMembers, t)
							}
						}
					}
				}
			}
			m.Units[full] = Unit{
				Interface:   iname,
				Unit:        uname,
				Inet:        orEmpty(inetAddrs),
				VLANMembers: orEmpty(vlanMembers),
			}
		}
	}

	for _, v := range conf.kid("vlans").kids("vlan") {
		vname, ok := v.txt("name")
		if !ok {
			continue
		}
		m.VLANs[vname] = VLAN{
			VlanID:      txtPtr(v, "vlan-id"),
			L3Interface: txtPtr(v, "l3-interface"),
			Members:     []string{},
		}
	}
	attachVLANMembers(m)

	sec := conf.kid("security")

	for _, ids := range sec.kid("screen").kids("ids-option") {
		if n, ok := ids.txt("name"); ok {
			m.Screens = append(m.Screens, n)
		}
	}

	for _, z := range sec.kid("zones").kids("security-zone") {
		zn, _ := z.txt("name")
		var ifaces []string
		for _, i := range z.kids("interfaces") {
			if n, ok := i.txt("name"); ok {
				ifaces = append(ifaces, n)
			}
		}
		var book *AddressBook
		if ab := z.kid("address-book"); ab != nil {
			b := parseAddressBookXML(ab)
			book = &b
		}
		hit := z.kid("host-inbound-traffic")
		m.Zones[zn] = Zone{
			Interfaces:     orEmpty(ifaces),
			LegacyBook:     book,
			SystemServices: orEmpty(hit.nameList("system-services")),
			Protocols:      orEmpty(hit.nameList("protocols")),
			Screen:         txtPtr(z, "screen"),
		}
	}

	for _, ab := range sec.kids("address-book") {
		bn, ok := ab.txt("name")
		if !ok {
			bn = "global"
		}
		b := parseAddressBookXML(ab)
		var zlist []string
		if attach := ab.kid("attach"); attach != nil {
			for _, zt := range attach.kids("zone") {
				if zn, ok := zt.txt("name"); ok {
					zlist = append(zlist, zn)
				} else if t := trimSpace(zt.Text); t != "" {
					zlist = append(zlist, t)
				}
			}
		}
		m.GlobalBooks[bn] = GlobalBook{
			Addresses:   b.Addresses,
			AddressSets: b.AddressSets,
			Zones:       orEmpty(zlist),
		}
	}

	for _, pblock := range sec.kid("policies").kids("policy") {
		fz, _ := pblock.txt("from-zone-name")
		tz, _ := pblock.txt("to-zone-name")
		for _, pol := range pblock.kids("policy") {
			pn, _ := pol.txt("name")
			match := pol.kid("match")
			p := Policy{
				FromZone:    fz,
				ToZone:      tz,
				Name:        pn,
				Source:      orAny(refList(match, "source-address")),
				Destination: orAny(refList(match, "destination-address")),
				Application: orAny(refList(match, "application")),
				Action:      "permit",
				Flags:       []string{},
				Logs:        []string{},
			}
			if then := pol.kid("then"); then != nil {
				action := ""
				for _, c := range then.Children {
					switch c.Tag {
					case "permit", "deny", "reject":
						action = c.Tag
					case "log":
						for _, lc := range c.Children {
							p.Flags = append(p.Flags, "log "+lc.Tag)
							p.Logs = append(p.Logs, lc.Tag)
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

	computePublicZones(m)
	finalizeModel(m)
	return m
}

// parseAddressBookXML : port de parse_address_book_body() (srxtool.py L376-401).
func parseAddressBookXML(ab *XMLNode) AddressBook {
	book := AddressBook{
		Addresses:   map[string]*string{},
		AddressSets: map[string]AddressSet{},
	}
	if ab == nil {
		return book
	}
	for _, a := range ab.kids("address") {
		an, ok := a.txt("name")
		if !ok {
			continue
		}
		var pfx *string
		if v, ok := a.txt("ip-prefix"); ok {
			pfx = strPtr(v)
		}
		if pfx == nil {
			if dn := a.kid("dns-name"); dn != nil {
				v, _ := dn.txt("name")
				pfx = strPtr("dns:" + v)
			}
			if rng := a.kid("range-address"); rng != nil {
				v, _ := rng.txt("name")
				pfx = strPtr("range:" + v)
			}
		}
		book.Addresses[an] = pfx
	}
	for _, s := range ab.kids("address-set") {
		sn, ok := s.txt("name")
		if !ok {
			continue
		}
		var mem, smem []string
		for _, x := range s.kids("address") {
			if n, ok := x.txt("name"); ok {
				mem = append(mem, n)
			}
		}
		for _, x := range s.kids("address-set") {
			if n, ok := x.txt("name"); ok {
				smem = append(smem, n)
			}
		}
		book.AddressSets[sn] = AddressSet{Addresses: orEmpty(mem), AddressSets: orEmpty(smem)}
	}
	return book
}

func refList(match *XMLNode, tag string) []string {
	if match == nil {
		return nil
	}
	var out []string
	for _, x := range match.kids(tag) {
		if v := x.addrRef(); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func txtPtr(x *XMLNode, name string) *string {
	if v, ok := x.txt(name); ok {
		return strPtr(v)
	}
	return nil
}

func trimSpace(s string) string { return strings.TrimSpace(s) }
