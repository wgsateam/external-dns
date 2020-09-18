package wunderdns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"sigs.k8s.io/external-dns/endpoint"
	"strings"
	"time"
)

type data map[string]interface{}
type reply struct {
	Status string `json:"status"`
	Data   data   `json:"data"`
}

type record struct {
	view  string
	name  string
	rtype string
	data  []string
	ttl   int
}

func parseData(data []byte) (data, error) {
	rep := &reply{}
	if e := json.Unmarshal(data, rep); e != nil {
		return nil, e
	}
	if rep.Status != "SUCCESS" {
		if e, ok := rep.Data["error"]; ok {
			return nil, errors.New(e.(string)) // error is always a string
		}
	}
	return rep.Data, nil
}
func (p *Provider) makeRequest(context context.Context, endpoint, method string, body []byte) (data, error) {
	if path, e := url.Parse(endpoint); e == nil {
		u2 := p.url.ResolveReference(path)
		if req, e := http.NewRequestWithContext(context, method, u2.String(), bytes.NewBuffer(body)); e == nil {
			req.Header.Add("X-API-Token", p.token)
			req.Header.Add("X-API-Secret", p.secret)
			req.Header.Add("Content-Type", "application/json")
			if resp, e := p.httpClient.Do(req); e == nil {
				defer resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					if b, e := ioutil.ReadAll(resp.Body); e == nil {
						return parseData(b)
					} else {
						return nil, e
					}
				}
				return nil, errors.New(fmt.Sprintf("HTTP code %s", resp.Status))
			} else {
				return nil, e
			}
		} else {
			return nil, e
		}
	} else {
		return nil, e
	}
}

func (p *Provider) createRecord(ctx context.Context, r *record) error {
	return nil
}

func (p *Provider) updateRecord(ctx context.Context, r *record) error {
	return nil
}

func (p *Provider) deleteRecord(ctx context.Context, r *record) error {
	return nil
}

func (p *Provider) guessDomain(ctx context.Context, r *record) (string, error) {
	now := time.Now().Unix()
	if now > p.domainsCacheTTL+domainsCacheExpiry {
		if e := p.updateDomainCache(ctx); e != nil {
			return "", e
		}

	}
	var domain string
	// get max matching domain backwards from .
	parts := strings.Split(r.name,".")
	for i := len(parts)-1;i>=0;i-- {
		temp := strings.Join(parts[i:], ".")
		if _, ok := p.domainsCache[r.view][temp]; ok {
			domain = temp
		}
	}
	return domain, nil
}

func (p *Provider) updateDomainCache(ctx context.Context) error {
	if data, e := p.makeRequest(ctx, "GET", "domain", []byte{}); e != nil {
		return e
	} else {
		// {"status":"SUCCESS","data": { "public": [ { "n": "domain", "t" : "public" } ], "private": [ { "n": "domain", "t" : "private" } ] } }
		for view, elems := range data {
			if !(view == viewPublic || view == viewPrivate) {
				continue // unknown view!
			}
			domains, ok := elems.([]interface{})
			if !ok {
				continue // not an array
			}
			for _, elem := range domains {
				domain, ok := elem.(map[string]interface{})
				if !ok {
					continue // not a hash
				}
				p.domainsCache[view][domain["n"].(string)] = true
			}
		}
		p.domainsCacheTTL = time.Now().Unix()

	}
	return nil
}
func (p *Provider) getMyRecords(ctx context.Context) ([]*record, error) {
	ret := make([]*record, 0)
	if data, e := p.makeRequest(ctx, "GET", "record?own", []byte{}); e == nil {
		// {"status":"SUCCESS","data":{"public":[{"d":["data1", "data2"],"f":false,"l":0,"n":"record_name","t":"A"}]}}
		for view, elems := range data {
			if !(view == viewPublic || view == viewPrivate) {
				continue // unknown view!
			}
			records, ok := elems.([]interface{})
			if !ok {
				continue // not an array
			}
			for _, elem := range records {
				rec, ok := elem.(map[string]interface{})
				if !ok {
					continue // not a hash
				}
				r := &record{view: view}
				r.name = rec["n"].(string)
				r.ttl = rec["l"].(int)
				r.rtype = rec["t"].(string)
				r.data = rec["d"].([]string)
				ret = append(ret, r)
			}
		}
		return ret, nil
	} else {
		return nil, e
	}

}

func (p *Provider) endpoint(r *record) *endpoint.Endpoint {
	return &endpoint.Endpoint{
		DNSName:          r.name,
		Targets:          r.data,
		RecordType:       r.rtype,
		SetIdentifier:    "",
		RecordTTL:        endpoint.TTL(r.ttl),
		Labels:           endpoint.Labels{"view": r.view},
		ProviderSpecific: nil,
	}
}

func (p *Provider) record(e *endpoint.Endpoint) *record {
	return &record{
		view:  p.guessView(e),
		name:  e.DNSName,
		rtype: e.RecordType,
		data:  e.Targets,
		ttl:   int(e.RecordTTL),
	}
}
