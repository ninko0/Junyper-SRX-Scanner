package audit

import (
	"fmt"
	"strings"

	"github.com/local/srxtool-go/internal/config"
)

// flagServiceSpec describes a system service to flag if present, port of
// the 7 flag_service() calls (srxaudit.py L515-529). Dynamically generates
// the SYS-TELNET, SYS-FTP, SYS-FINGER, SYS-RLOGIN, SYS-RSH,
// SYS-TFTP-SERVER, SYS-XNM-CLEAR-TEXT codes — easy to miss with a simple
// grep for literals, hence this explicit list (cf task 09).
type flagServiceSpec struct {
	tag   string
	sev   Severity
	title string
	reco  string
	ref   string
}

var flaggedServices = []flagServiceSpec{
	{"telnet", High, "Telnet enabled", "Disable Telnet, use SSH.", "CIS Juniper; charter §3.4"},
	{"ftp", Medium, "FTP server enabled", "Disable cleartext FTP, prefer SCP/SFTP.", "CIS Juniper"},
	{"finger", Medium, "finger service enabled", "Disable finger (information disclosure).", "CIS Juniper"},
	{"rlogin", High, "rlogin enabled", "Disable rlogin (cleartext).", "CIS Juniper"},
	{"rsh", High, "rsh enabled", "Disable rsh (cleartext).", "CIS Juniper"},
	{"tftp-server", Medium, "TFTP server enabled", "Disable TFTP (no authentication).", "CIS Juniper"},
	{"xnm-clear-text", High, "XNM in cleartext (unencrypted NETCONF)", "Disable xnm-clear-text, use NETCONF over SSH.", "CIS Juniper"},
}

// checkSystem: port of check_system() (srxaudit.py L503-633).
//
// system/snmp are the raw config.Model.System / .SNMP subtrees, navigated
// via the Tree interface common to text and XML (task 01) — where Python
// tested `isinstance(system, dict)` on every access, here a single code
// path handles both formats.
func checkSystem(system, snmp config.Tree) ([]Finding, error) {
	var out []Finding
	services := system.Sub("services")

	if config.Exists(services) {
		for _, spec := range flaggedServices {
			if services.Has(spec.tag) {
				out = append(out, Finding{
					Severity: spec.sev, Check: "SYS-" + strings.ToUpper(spec.tag),
					Title: spec.title, Where: "system services " + spec.tag,
					Reco: spec.reco, Ref: spec.ref,
					Fix: []string{"delete system services " + spec.tag},
				})
			}
		}

		if ssh := services.Sub("ssh"); config.Exists(ssh) {
			if rl, _ := ssh.Val("root-login"); rl == "allow" {
				out = append(out, Finding{
					Severity: High, Check: "SYS-SSH-ROOT", Title: "SSH root-login allowed",
					Where: "system services ssh root-login allow",
					Reco:  "Forbid direct root login via SSH.", Ref: "CIS Juniper",
					Fix: []string{"set system services ssh root-login deny"},
				})
			}
			if pv, _ := ssh.Val("protocol-version"); strings.ToLower(pv) == "v1" {
				out = append(out, Finding{
					Severity: High, Check: "SYS-SSH-V1", Title: "SSH protocol v1 allowed",
					Where: "system services ssh protocol-version v1",
					Reco:  "Force SSHv2 only.", Ref: "CIS Juniper",
					Fix: []string{"set system services ssh protocol-version v2"},
				})
			}
		}

		if web := services.Sub("web-management"); config.Exists(web) && web.Has("http") {
			out = append(out, Finding{
				Severity: High, Check: "SYS-WEBMGMT-HTTP", Title: "Web-management over HTTP (unencrypted)",
				Where: "system services web-management http",
				Reco:  "Disable HTTP, only expose HTTPS for J-Web.", Ref: "CIS Juniper",
				Fix: []string{"delete system services web-management http"},
			})
		}
	}

	// syslog/ntp/login are tested OUTSIDE the Python `if services is not
	// None`: they apply even if `system { }` has no `services`.
	syslog := system.Sub("syslog")
	remoteHosts := 0
	if config.Exists(syslog) {
		remoteHosts = len(syslog.SubAll("host"))
	}
	if remoteHosts == 0 {
		out = append(out, Finding{
			Severity: Medium, Check: "SYS-NO-SYSLOG", Title: "No remote logging (syslog host)",
			Where: "system syslog",
			Reco:  "Send logs to an external collector/SIEM (traceability, retention, correlation).",
			Ref:   "NIS2 21.2(g)",
			Fix:   []string{"# set system syslog host <SIEM_IP> any info"},
		})
	}

	ntp := system.Sub("ntp")
	hasNTPServer := config.Exists(ntp) && (len(ntp.Vals("server")) > 0 || len(ntp.SubAll("server")) > 0)
	if !hasNTPServer {
		out = append(out, Finding{
			Severity: Low, Check: "SYS-NO-NTP", Title: "NTP not configured",
			Where: "system ntp",
			Reco:  "Synchronize the clock (essential for log timestamping).",
			Ref:   "CIS Juniper",
			Fix:   []string{"# set system ntp server <NTP_IP>"},
		})
	}

	login := system.Sub("login")
	msg := ""
	if config.Exists(login) {
		msg, _ = login.Val("message")
	}
	if !config.Exists(login) || msg == "" {
		out = append(out, Finding{
			Severity: Low, Check: "SYS-NO-BANNER", Title: "No login banner",
			Where: "system login message",
			Reco:  "Display a legal warning at login.",
			Ref:   "CIS Juniper",
			Fix:   []string{`# set system login message "Access restricted - authorized use only"`},
		})
	}

	if config.Exists(snmp) {
		communities := snmp.SubAllNamed("community")
		hadAny := len(communities) > 0
		for _, com := range communities {
			cname := com.Name
			auth := config.ValOr(com.Node, "authorization", "read-only")

			if cname != "" && (strings.ToLower(cname) == "public" || strings.ToLower(cname) == "private") {
				cq, err := q(cname)
				if err != nil {
					return nil, err
				}
				out = append(out, Finding{
					Severity: High, Check: "SNMP-DEFAULT-COMM",
					Title: fmt.Sprintf("Default SNMP community: '%s'", cname),
					Where: "snmp community " + cq,
					Reco:  "Remove the public/private communities, prefer SNMPv3.",
					Ref:   "CIS Juniper",
					Fix:   []string{"delete snmp community " + cq},
				})
			}
			if auth == "read-write" {
				cq, err := q(cname)
				if err != nil {
					return nil, err
				}
				out = append(out, Finding{
					Severity: High, Check: "SNMP-RW",
					Title: fmt.Sprintf("SNMP community with write access: '%s'", cname),
					Where: "snmp community " + cq + " authorization read-write",
					Reco:  "Avoid read-write SNMP (especially v1/v2c).",
					Ref:   "CIS Juniper",
				})
			}
		}
		hasV3 := config.Exists(snmp.Sub("v3"))
		if hadAny && !hasV3 {
			out = append(out, Finding{
				Severity: Medium, Check: "SNMP-NO-V3", Title: "SNMP v1/v2c in use, no v3",
				Where: "snmp",
				Reco:  "Migrate to SNMPv3 (auth + encryption).",
				Ref:   "CIS Juniper",
			})
		}
	}

	return out, nil
}
