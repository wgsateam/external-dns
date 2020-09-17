package wunderdns

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
	"sigs.k8s.io/external-dns/provider"
	"strings"
)

const (
	viewPrivate = "private"
	viewPublic  = "public"
)

type Provider struct {
	provider.BaseProvider
	url          *url.URL
	token        string
	secret       string
	verify       bool
	privateNets  []*net.IPNet
	domainFilter endpoint.DomainFilter
	httpClient   *http.Client
}

func NewProvider(domainFilter endpoint.DomainFilter, confUrl, confToken, confSecret string, confVerify bool) (*Provider, error) {
	blocks := make([]*net.IPNet, 0)
	for _, cidr := range []string{
		"127.0.0.0/8",    // IPv4 loopback
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"169.254.0.0/16", // RFC3927 link-local
		"::1/128",        // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
		"fc00::/7",       // IPv6 unique local addr
	} {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		blocks = append(blocks, block)
	}
	u, e := url.Parse(confUrl)
	if e != nil {
		return nil, e
	}
	return &Provider{
		url:          u,
		token:        confToken,
		secret:       confSecret,
		verify:       confVerify,
		domainFilter: domainFilter,
		privateNets:  blocks,
		httpClient: &http.Client{
			Transport:     &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: !confVerify}},
			CheckRedirect: nil,
			Jar:           nil,
			Timeout:       0,
		},
	}, nil
}

func (w *Provider) isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	for _, n := range w.privateNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (w *Provider) guessView(e endpoint.Endpoint) string {
	// guess view by looking at targets
	if v, ok := e.Labels["view"]; ok {
		v = strings.ToLower(v) // go lower
		if v == viewPublic || v == viewPrivate {
			return v // has view
		}
	}
	if e.RecordType == "A" || e.RecordType == "AAAA" {
		for _, d := range e.Targets {
			if ip := net.ParseIP(d); ip != nil {
				if w.isPrivateIP(ip) {
					return viewPrivate
				} else {
					return viewPublic
				}

			}
		}
	} else if e.RecordType == "CNAME" {
		for _, d := range e.Targets {
			if ipa, e := net.ResolveIPAddr("", d); e == nil {
				if w.isPrivateIP(ipa.IP) {
					return viewPrivate
				} else {
					return viewPublic
				}
			}
		}
	} else if e.RecordType == "SRV" {
		for _, d := range e.Targets {
			t := strings.Split(d, " ") // get last part of SRV record
			if ipa, e := net.ResolveIPAddr("", t[len(t)-1]); e == nil {
				if w.isPrivateIP(ipa.IP) {
					return viewPrivate
				} else {
					return viewPublic
				}
			}
		}
	} else if e.RecordType == "TXT" { // assume TXT is for external use
		return viewPublic
	}
	return viewPrivate // all other stuff is private
}

func (p *Provider) Records(ctx context.Context) ([]*endpoint.Endpoint, error) {
	if records, e := p.getMyRecords(ctx); e != nil {
		return nil, e
	} else {
		ret := make([]*endpoint.Endpoint, len(records))
		for i, rec := range records {
			ret[i] = rec.endpoint()
		}
		return ret, nil
	}
}

func (p *Provider) ApplyChanges(ctx context.Context, changes *plan.Changes) error {
	return nil
}
