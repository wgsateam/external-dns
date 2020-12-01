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
	if n, _ := p.guessDomain(nil, &record{view: viewPublic, name: "fixme.test.net"}); n != "test.net" {
		t.Errorf("fixme.test.net failed %s", n)
	}
	if n, _ := p.guessDomain(nil, &record{view: viewPublic, name: "fixme.eu.test.net"}); n != "eu.test.net" {
		t.Errorf("fixme.eu.test.net failed %s", n)
	}
	if n, _ := p.guessDomain(nil, &record{view: viewPublic, name: "fixme.aa.test.net"}); n != "test.net" {
		t.Errorf("fixme.aa.test.net failed %s", n)
	}
	if n, _ := p.guessDomain(nil, &record{view: viewPublic, name: "fixme.aa.eu.test.net"}); n != "aa.eu.test.net" {
		t.Errorf("fixme.test.net failed: %s", n)
	}
}

func TestAnyToAny(t *testing.T) {
	if any2string(10) != "10" {
		t.Errorf("a2s: 10 != 10")
	}
	if any2string([]byte{'a', 'b', 'c', 'd'}) != "abcd" {
		t.Errorf("abcd != abcd")
	}

	if any2int(10.0) != 10 {
		t.Errorf("10.0 != 10")
	}
	any2i := map[interface{}]int{
		"10":     10,
		"10abcd": 10,
		"10.5":   10,
	}

	for k, v := range any2i {
		if any2int(k) != v {
			t.Errorf("any2int failed: %v != %d", k, v)
		}
	}
	k := []interface{}{"abcd", "bcda", 10, []byte{'a', 'b', 'a', 'c', 'd'}}
	v := []string{"abcd", "bcda", "10", "abacd"}
	v2 := any2strings(k)

	if len(v) != len(v2) {
		t.Errorf("any2strings: array length mistmatch")
	}
	for i := 0; i < len(v); i++ {
		if v[i] != v2[i] {
			t.Errorf("any2strings:[%d]: %s != %s", i, v[i], v2[i])
		}
	}

}
