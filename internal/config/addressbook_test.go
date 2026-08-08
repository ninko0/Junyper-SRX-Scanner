package config

import (
	"reflect"
	"testing"
)

// TestAddressBookForms covers checklist 09's "address-book { global {
// ... } } vs zone address-book" line.
//
// The `address-book { global { ... } }` case is DELIBERATE DIVERGENCE
// #1: the reference Python returns an empty global book here (bug
// verified against the source code). This test locks in the fixed
// behavior — if it ever fails, someone "realigned" Go with the Python
// bug.
func TestAddressBookForms(t *testing.T) {
	conf := `security {
    address-book {
        global {
            address srv-web 10.1.1.10/32;
            address-set web-farm {
                address srv-web;
            }
            attach {
                zone dmz;
            }
        }
    }
    zones {
        security-zone dmz {
            interfaces {
                ge-0/0/5.0;
            }
            address-book {
                address local-1 10.2.2.2/32;
            }
        }
    }
}
`
	m, err := Parse([]byte(conf), Options{})
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}

	gb, ok := m.GlobalBooks["global"]
	if !ok {
		t.Fatal("global book missing")
	}
	if gb.Addresses["srv-web"] == nil || *gb.Addresses["srv-web"] != "10.1.1.10/32" {
		t.Errorf("global object lost: %+v", gb.Addresses)
	}
	if !reflect.DeepEqual(gb.AddressSets["web-farm"].Addresses, []string{"srv-web"}) {
		t.Errorf("global address-set lost: %+v", gb.AddressSets)
	}
	if !reflect.DeepEqual(gb.Zones, []string{"dmz"}) {
		t.Errorf("attach zone: %v", gb.Zones)
	}

	z := m.Zones["dmz"]
	if z.LegacyBook == nil {
		t.Fatal("zone legacy book missing")
	}
	if z.LegacyBook.Addresses["local-1"] == nil || *z.LegacyBook.Addresses["local-1"] != "10.2.2.2/32" {
		t.Errorf("zone object lost: %+v", z.LegacyBook.Addresses)
	}
}

// TestAddressBookNamed: `address-book <name> { ... }` form (original
// Python behavior, kept).
func TestAddressBookNamed(t *testing.T) {
	conf := `security {
    address-book book-1 {
        address a1 192.168.5.5/32;
    }
    zones {
        security-zone trust {
            interfaces {
                ge-0/0/0.0;
            }
        }
    }
}
`
	m, err := Parse([]byte(conf), Options{})
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}
	b, ok := m.GlobalBooks["book-1"]
	if !ok {
		t.Fatalf("named book missing: %v", m.GlobalBooks)
	}
	if b.Addresses["a1"] == nil || *b.Addresses["a1"] != "192.168.5.5/32" {
		t.Errorf("missing object: %+v", b.Addresses)
	}
}

// TestAddressBookSetFormat: the flattened `display set` form must
// produce the same result (`address NAME PREFIX` becomes
// address { NAME { PREFIX; } }).
func TestAddressBookSetFormat(t *testing.T) {
	conf := `set security zones security-zone trust interfaces ge-0/0/0.0
set security zones security-zone trust address-book address h1 10.9.9.9/32
set security zones security-zone trust address-book address-set grp address h1
set security address-book global address g1 172.20.0.1/32
`
	m, err := Parse([]byte(conf), Options{})
	if err != nil {
		t.Fatalf("parsing failed: %v", err)
	}
	if m.SourceFormat != "set" {
		t.Fatalf("detected format: %q", m.SourceFormat)
	}
	lb := m.Zones["trust"].LegacyBook
	if lb == nil || lb.Addresses["h1"] == nil || *lb.Addresses["h1"] != "10.9.9.9/32" {
		t.Fatalf("incorrect zone book: %+v", lb)
	}
	if !reflect.DeepEqual(lb.AddressSets["grp"].Addresses, []string{"h1"}) {
		t.Errorf("address-set: %+v", lb.AddressSets)
	}
	gb := m.GlobalBooks["global"]
	if gb.Addresses["g1"] == nil || *gb.Addresses["g1"] != "172.20.0.1/32" {
		t.Errorf("global book: %+v", gb.Addresses)
	}
}
