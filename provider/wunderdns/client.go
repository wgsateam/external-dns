package wunderdns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"net/url"
	"runtime"
	"sigs.k8s.io/external-dns/endpoint"
	"strconv"
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

func debug(v ...interface{}) {
	if _, file, line, ok := runtime.Caller(3); ok {
		pfx := file
		for i := 0; i < len(file); i++ {
			if file[i] == '/' {
				pfx = file[i+1:]
			}
		}
		pfx = string(append(append([]byte(pfx), ':'), []byte(strconv.Itoa(line))...))
		log.Debug(append([]interface{}{pfx}, v...)...)
	} else {
		log.Debug(v...)
	}
}

func parseData(data []byte) (data, error) {
	debug("parseData: ", string(data))
	rep := &reply{}
	if e := json.Unmarshal(data, rep); e != nil {
		return nil, e
	}
	if rep.Status != "SUCCESS" {
		if err, ok := rep.Data["error"]; ok {
			switch err.(type) {
			case string:
				return nil, errors.New(err.(string))
			default:
				return nil, errors.New(fmt.Sprintf("%v", err))

			}
		}
	}
	return rep.Data, nil
}
func (p *Provider) makeRequest(context context.Context, endpoint, method string, body []byte) (data, error) {
	debug("makeRequest: ", endpoint, " ", method, " ", string(body))
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
	if domain, e := p.guessDomain(ctx, r); e != nil {
		return e
	} else {
		recName := p.getRecord(ctx, r, domain)
		data := map[string]interface{}{
			"domain": domain,
			"record": []interface{}{
				map[string]interface{}{
					"target": recName,
					"type":   r.rtype,
					"view":   r.view,
					"ttl":    r.ttl,
					"data":   r.data,
				},
			},
		}
		if d, e := json.Marshal(data); e != nil {
			return e
		} else {
			if _, e := p.makeRequest(ctx, "record", "POST", d); e == nil {
				return e
			}
			return e
		}
	}
}

func (p *Provider) updateRecord(ctx context.Context, r *record) error {
	if domain, e := p.guessDomain(ctx, r); e != nil {
		return e
	} else {
		recName := p.getRecord(ctx, r, domain)
		data := map[string]interface{}{
			"domain": domain,
			"record": []interface{}{
				map[string]interface{}{
					"target": recName,
					"type":   r.rtype,
					"view":   r.view,
					"ttl":    r.ttl,
					"data":   r.data,
				},
			},
		}
		if d, e := json.Marshal(data); e != nil {
			return e
		} else {
			if _, e := p.makeRequest(ctx, "record", "PUT", d); e == nil {
				return e
			}
			return e
		}
	}
}

func (p *Provider) deleteRecord(ctx context.Context, r *record) error {
	if domain, e := p.guessDomain(ctx, r); e != nil {
		return e
	} else {
		recName := p.getRecord(ctx, r, domain)
		data := map[string]interface{}{
			"domain": domain,
			"record": []interface{}{
				map[string]interface{}{
					"target": recName,
					"type":   r.rtype,
					"view":   r.view,
					"ttl":    r.ttl,
					"data":   r.data,
				},
			},
		}
		if d, e := json.Marshal(data); e != nil {
			return e
		} else {
			if _, e := p.makeRequest(ctx, "record", "DELETE", d); e == nil {
				return e
			}
			return e
		}
	}
}

func (p *Provider) getRecord(ctx context.Context, r *record, domain string) string {
	recName := strings.ReplaceAll(r.name, fmt.Sprintf(".%s", domain), "")
	if recName != domain {
		return recName
	} else {
		return "."
	}
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
	parts := strings.Split(r.name, ".")
	for i := len(parts) - 1; i >= 0; i-- {
		temp := strings.Join(parts[i:], ".")
		if _, ok := p.domainsCache[r.view][temp]; ok {
			domain = temp
		}
	}
	return domain, nil
}

func (p *Provider) updateDomainCache(ctx context.Context) error {
	if data, e := p.makeRequest(ctx, "domain", "GET", []byte{}); e != nil {
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

func any2string(v interface{}) string {
	switch v.(type) {
	case string:
		return v.(string)
	case []byte:
		return string(v.([]byte))
	default:
		return fmt.Sprintf("%v", v)
	}
}

func any2int(v interface{}) int {
	switch v.(type) {
	case int:
		return v.(int)
	case float64:
		return int(v.(float64))
	default:
		v := fmt.Sprintf("%v", v)
		for i := 0; i < len(v); i++ {
			if v[i] >= '0' && v[i] <= '9' {
				continue
			}
			v = v[:i]
			break
		}
		i, _ := strconv.Atoi(v)
		return i
	}
}

func any2strings(v interface{}) []string {
	switch v.(type) {
	case []string:
		return v.([]string)
	case []interface{}:
		r := make([]string, len(v.([]interface{})))
		for i := 0; i < len(r); i++ {
			r[i] = any2string(v.([]interface{})[i])
		}
		return r
	default:
		return []string{any2string(v)}
	}
}
func (p *Provider) getMyRecords(ctx context.Context) ([]*record, error) {
	ret := make([]*record, 0)
	if data, e := p.makeRequest(ctx, "record?own", "GET", []byte{}); e == nil {
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
				r.name = any2string(rec["n"])
				r.ttl = any2int(rec["l"])
				r.rtype = any2string(rec["t"])
				r.data = any2strings(rec["d"])
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
