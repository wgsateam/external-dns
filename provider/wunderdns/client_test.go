package wunderdns

import (
	"testing"
	"time"
)

func TestGuessDomain(t *testing.T) {
	p := Provider{domainsCacheTTL: time.Now().Unix()}
	p.domainsCache = map[string]map[string]bool{
		viewPublic: {
			"test.net":       true,
			"eu.test.net":    true,
			"aa.eu.test.net": true,
		},
	}
	if n, _ := p.guessDomain(nil, &record{view:viewPublic,name:"fixme.test.net"}); n != "test.net" {
		t.Errorf("fixme.test.net failed %s", n)
	}
	if n, _ := p.guessDomain(nil, &record{view:viewPublic,name:"fixme.eu.test.net"}); n != "eu.test.net" {
		t.Errorf("fixme.eu.test.net failed %s", n)
	}
	if n, _ := p.guessDomain(nil, &record{view:viewPublic,name:"fixme.aa.test.net"}); n != "test.net" {
		t.Errorf("fixme.aa.test.net failed %s", n)
	}
	if n, _ := p.guessDomain(nil, &record{view:viewPublic,name:"fixme.aa.eu.test.net"}); n != "aa.eu.test.net" {
		t.Errorf("fixme.test.net failed: %s", n)
	}
}
