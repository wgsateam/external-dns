package wunderdns

import (
	"context"
	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
	"sigs.k8s.io/external-dns/provider"
)

type WunderDNSProvider struct {
	provider.BaseProvider
	url          string
	token        string
	secret       string
	verify       bool
	domainFilter endpoint.DomainFilter
}

func NewProvider(domainFilter endpoint.DomainFilter, url, token, secret string, verify bool) (*WunderDNSProvider, error) {
	return &WunderDNSProvider{
		url:          url,
		token:        token,
		secret:       secret,
		verify:       verify,
		domainFilter: domainFilter,
	}, nil
}

func (w *WunderDNSProvider) Records(ctx context.Context) ([]*endpoint.Endpoint, error) {
	return nil, nil
}
func (w *WunderDNSProvider) ApplyChanges(ctx context.Context, changes *plan.Changes) error {
	return nil
}
