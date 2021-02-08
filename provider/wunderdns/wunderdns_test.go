package wunderdns

import (
	"net"
	"sigs.k8s.io/external-dns/endpoint"
	"testing"
)

func TestIsPrivateIP(t *testing.T) {
	p, _ := NewProvider(endpoint.DomainFilter{}, "", "", "", false)
	if !p.isPrivateIP(net.ParseIP("192.168.1.1")) {
		t.Errorf("TestIsPrivateIP(192.168.0.1) failed")
	}
	if !p.isPrivateIP(net.ParseIP("127.0.0.2")) {
		t.Errorf("TestIsPrivateIP(127.0.0.2) failed")
	}
	if p.isPrivateIP(net.ParseIP("8.8.8.8")) {
		t.Errorf("TestIsPrivateIP(8.8.8.8) failed")
	}
}

func TestGuessView(t *testing.T) {
	p, _ := NewProvider(endpoint.DomainFilter{}, "", "", "", false)

	if p.guessView(endpoint.NewEndpoint("abcd.test.com", "A", "192.168.0.1")) != viewPrivate {
		t.Errorf("TestGuessView(A) failed")
	}
	if p.guessView(endpoint.NewEndpoint("abcd.test.com", "CNAME", "dns.google.com")) != viewPublic {
		t.Errorf("TestGuessView(CNAME) failed")
	}
	if p.guessView(endpoint.NewEndpoint("abcd.test.com", "TXT", "dns.google.com")) != viewPrivate {
		t.Errorf("TestGuessView(TXT) failed")
	}
	if p.guessView(endpoint.NewEndpoint("abcd.test.com", "SRV", "10 60 5060 dns.google.com")) != viewPublic {
		t.Errorf("TestGuessView(SRV) failed")
	}
}
