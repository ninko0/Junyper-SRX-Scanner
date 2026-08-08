package rules

import (
	"reflect"
	"strings"
	"testing"

	"github.com/local/srxtool-go/internal/inventory"
)

func TestIPNamed(t *testing.T) {
	strp := func(s string) *string { return &s }
	cases := []struct {
		name   string
		prefix *string
		wantIP string
		wantOK bool
	}{
		{"10.10.10.50", nil, "10.10.10.50", true},
		{"h-10.10.10.50", nil, "10.10.10.50", true},
		{"host_10.10.10.50", nil, "10.10.10.50", true},
		{"net-10.10.10.0/24", nil, "10.10.10.0/24", true},
		{"10.10.10.50_32", nil, "10.10.10.50/32", true},
		{"web-server-prod", nil, "", false},
		{"corp-servers", nil, "", false},
		{"999.1.1.1", nil, "", false},                                      // octet out of range
		{"10.10.10.50/32", strp("10.10.10.50/32"), "10.10.10.50/32", true}, // name == prefix
		{"toolong-prefix-h-10.10.10.50", nil, "", false},                   // prefix > 6 letters
	}
	for _, c := range cases {
		gotIP, gotOK := IPNamed(c.name, c.prefix)
		if gotOK != c.wantOK || (gotOK && gotIP != c.wantIP) {
			t.Errorf("IPNamed(%q) = (%q,%v), expected (%q,%v)", c.name, gotIP, gotOK, c.wantIP, c.wantOK)
		}
	}
}

func TestAppRole(t *testing.T) {
	cases := []struct {
		apps []string
		want string
	}{
		{[]string{"junos-https"}, "web"},
		{[]string{"junos-http"}, "web"},
		{[]string{"junos-ssh"}, "ssh"},
		{[]string{"junos-ms-rdp"}, "rdp"},
		{[]string{"custom-mysql-app"}, "db"},
		{[]string{"junos-ldap"}, "ldap"},
		{[]string{"junos-dns-udp"}, "dns"},
		{[]string{"junos-smtp"}, "mail"},
		{[]string{"cifs"}, "file"},
		{[]string{"junos-ntp"}, "ntp"},
		{[]string{"junos-snmp"}, "snmp"},
		{[]string{"junos-syslog"}, "log"},
		{[]string{"totally-unknown-app"}, ""},
		{nil, ""},
		// Order: https should win over http if both are present (the first
		// matching hint in the list wins).
		{[]string{"junos-http", "junos-https"}, "web"},
	}
	for _, c := range cases {
		if got := AppRole(c.apps); got != c.want {
			t.Errorf("AppRole(%v) = %q, expected %q", c.apps, got, c.want)
		}
	}
}

func TestSuggestNameWithoutDNS(t *testing.T) {
	cases := []struct {
		prefix, zone string
		usages       []inventory.Usage
		want         string
	}{
		{"10.10.10.50/32", "trust", nil, "trust-host-50"},
		{"10.10.10.50/32", "", nil, "srv-host-50"},
		{"10.10.10.50/32", "TRUST", nil, "trust-host-50"}, // lowercased zone
		{"10.10.10.7/32", "dmz", []inventory.Usage{
			{Kind: "policy-dst", Apps: []string{"junos-https"}},
		}, "dmz-web-7"},
		{"10.10.10.7/32", "dmz", []inventory.Usage{
			// policy-src usage: ignored for the role (only policy-dst counts)
			{Kind: "policy-src", Apps: []string{"junos-https"}},
		}, "dmz-host-7"},
	}
	for _, c := range cases {
		if got := SuggestName(c.prefix, c.zone, c.usages, false); got != c.want {
			t.Errorf("SuggestName(%q,%q) = %q, expected %q", c.prefix, c.zone, got, c.want)
		}
	}
}

func TestReadRenameMapCSVValidatesNames(t *testing.T) {
	csvIn := "book,book_type,old_name,prefix,zones,refs,apps,suggested_new_name,new_name\n" +
		"trust,zone,10.10.10.50,10.10.10.50/32,trust,1,,trust-host-50,web-corp-01\n" +
		"trust,zone,10.10.10.51,10.10.10.51/32,trust,0,,trust-host-51,bad;name\n" +
		"trust,zone,10.10.10.52,10.10.10.52/32,trust,0,,trust-host-52,\n" // empty new_name -> ignored
	mapping, rejected, err := ReadRenameMapCSV(strings.NewReader(csvIn))
	if err != nil {
		t.Fatalf("ReadRenameMapCSV: %v", err)
	}
	if len(rejected) != 1 {
		t.Fatalf("expected 1 rejected line, got %d: %v", len(rejected), rejected)
	}
	want := map[RenameMapKey]string{{Book: "trust", OldName: "10.10.10.50"}: "web-corp-01"}
	if !reflect.DeepEqual(mapping, want) {
		t.Errorf("mapping = %v, expected %v", mapping, want)
	}
}
