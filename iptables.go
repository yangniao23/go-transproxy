package transproxy

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/coreos/go-iptables/iptables"
)

const (
	NAT        = "nat"
	PREROUTING = "PREROUTING"
	OUTPUT     = "OUTPUT"
)

type IPTables struct {
	iptables      *iptables.IPTables
	dnsTCPOutRule []string
	dnsTCPRule    []string
	dnsUDPRule    []string
	httpRule      []string
	httpsRule     []string
	tcpRule       []string
	err           error
}

type IPTablesConfig struct {
	DNSToPort   int
	HTTPToPort  int
	HTTPSToPort int
	TCPToPort   int
	TCPDPorts   []int
	PublicDNS   string
}

func NewIPTables(c *IPTablesConfig) (*IPTables, error) {
	GenerateRule := func(protocol string, dport int, tport int) []string {
		if dport == 0 || tport == 0 {
			return []string{""}
		} else {
			return []string{NAT, PREROUTING, "-p", "tcp", "--dport", strconv.Itoa(dport), "-j", "REDIRECT", "--to-ports", strconv.Itoa(tport)}
		}
	}

	t, err := iptables.New()
	if err != nil {
		return nil, err
	}

	var tcpDPorts []string
	for _, v := range c.TCPDPorts {
		tcpDPorts = append(tcpDPorts, strconv.Itoa(v))
	}

	var dnsTCPOutRule []string
	if c.PublicDNS != "" {
		_, _, err := net.SplitHostPort(c.PublicDNS)
		if err != nil {
			c.PublicDNS = net.JoinHostPort(c.PublicDNS, "53")
		}
		h, p, _ := net.SplitHostPort(c.PublicDNS)
		dnsTCPOutRule = []string{NAT, OUTPUT, "-p", "tcp", "-d", h, "--dport", p, "-j", "REDIRECT", "--to-ports", strconv.Itoa(c.TCPToPort)}
	}

	dnsTCPRule := GenerateRule("tcp", 53, c.DNSToPort)
	dnsUDPRule := GenerateRule("udp", 53, c.DNSToPort)
	httpRule := GenerateRule("tcp", 80, c.HTTPToPort)
	httpsRule := GenerateRule("tcp", 443, c.HTTPSToPort)
	tcpRule := []string{NAT, PREROUTING, "-p", "tcp", "-m", "multiport", "--dport", strings.Join(tcpDPorts, ","), "-j", "REDIRECT", "--to-ports", strconv.Itoa(c.TCPToPort)}

	if c.TCPToPort == 0 {
		dnsTCPOutRule = []string{""}
		tcpRule = []string{""}
	}

	for _, v := range tcpDPorts {
		if v == "0" {
			tcpRule = []string{""}
			break
		}
	}

	return &IPTables{
		iptables:      t,
		dnsTCPOutRule: dnsTCPOutRule,
		dnsTCPRule:    dnsTCPRule,
		dnsUDPRule:    dnsUDPRule,
		httpRule:      httpRule,
		httpsRule:     httpsRule,
		tcpRule:       tcpRule,
	}, nil
}

func (t *IPTables) Start() error {
	t.Check(t.dnsTCPOutRule)
	t.Check(t.dnsTCPRule)
	t.Check(t.dnsUDPRule)
	t.Check(t.httpRule)
	t.Check(t.httpsRule)
	t.Check(t.tcpRule)

	t.insertRule(t.dnsTCPOutRule)
	t.insertRule(t.dnsTCPRule)
	t.insertRule(t.dnsUDPRule)
	t.insertRule(t.httpRule)
	t.insertRule(t.httpsRule)
	t.insertRule(t.tcpRule)

	return t.err
}

func (t *IPTables) Stop() error {
	t.deleteRule(t.dnsTCPOutRule)
	t.deleteRule(t.dnsTCPRule)
	t.deleteRule(t.dnsUDPRule)
	t.deleteRule(t.httpRule)
	t.deleteRule(t.httpsRule)
	t.deleteRule(t.tcpRule)

	return t.err
}

func (t *IPTables) Show() string {
	rule := func(rules []string) string {
		if rules == nil {
			return "nil"
		} else {
			if rules[0] == "" {
				return ""
			} else {
				return fmt.Sprintf("iptables -t %s -I %s\n", rules[0], strings.Join(rules[1:], " "))
			}
		}
	}

	s := rule(t.tcpRule)
	s += rule(t.httpsRule)
	s += rule(t.httpRule)
	s += rule(t.dnsUDPRule)
	s += rule(t.dnsTCPRule)

	if len(t.dnsTCPOutRule) > 0 {
		s += fmt.Sprintf(`
iptables -t %s -I %s`,
			t.dnsTCPOutRule[0], strings.Join(t.dnsTCPOutRule[1:], " "),
		)
	}

	return s
}

func (t *IPTables) Check(rule []string) {
	if rule[0] == "" {
		return
	}
	if t.err != nil || len(rule) < 3 {
		return
	}

	exists, err := t.iptables.Exists(rule[0], rule[1], rule[2:]...)
	if exists {
		t.err = fmt.Errorf("same iptables rule already exists : iptables -t %s -I %s", rule[0], strings.Join(rule[1:], " "))
	}

	if err != nil {
		t.err = fmt.Errorf("checking iptables rule failed : %s", err.Error())
	}
}

func (t *IPTables) insertRule(rule []string) {
	if t.err != nil || len(rule) < 3 {
		return
	}

	if err := t.iptables.Insert(rule[0], rule[1], 1, rule[2:]...); err != nil {
		t.err = fmt.Errorf("insert iptables rule failed : %s", err.Error())
	}
}

func (t *IPTables) deleteRule(rule []string) {
	if rule[0] == "" {
		return
	}
	// Don't skip when it has error for deleting all rules
	if len(rule) < 3 {
		return
	}

	if err := t.iptables.Delete(rule[0], rule[1], rule[2:]...); err != nil {
		t.err = fmt.Errorf("Delete iptables rule failed : %s", err.Error())
	}
}
