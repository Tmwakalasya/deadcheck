package registry

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"github.com/tuntufye/deadcheck/internal/model"
)

type Client struct {
	httpClient *http.Client
	urls       URLs

	mu           sync.Mutex
	metaCache    map[string]PackageMetadata
	metaInflight map[string]*metaCall
	vulnCache    map[string][]Vulnerability
	vulnInflight map[string]*vulnCall
}

type metaCall struct {
	done  chan struct{}
	value PackageMetadata
	err   error
}

type vulnCall struct {
	done  chan struct{}
	value []Vulnerability
	err   error
}

func NewClient(httpClient *http.Client, urls URLs) *Client {
	return &Client{
		httpClient:   httpClient,
		urls:         urls,
		metaCache:    make(map[string]PackageMetadata),
		metaInflight: make(map[string]*metaCall),
		vulnCache:    make(map[string][]Vulnerability),
		vulnInflight: make(map[string]*vulnCall),
	}
}

func (c *Client) PackageMetadata(ctx context.Context, dep model.Dependency) (PackageMetadata, error) {
	key := string(dep.Ecosystem) + "|" + dep.Name
	c.mu.Lock()
	if cached, ok := c.metaCache[key]; ok {
		c.mu.Unlock()
		return cached, nil
	}
	if inflight, ok := c.metaInflight[key]; ok {
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			return PackageMetadata{}, ctx.Err()
		case <-inflight.done:
			return inflight.value, inflight.err
		}
	}

	call := &metaCall{done: make(chan struct{})}
	c.metaInflight[key] = call
	c.mu.Unlock()

	call.value, call.err = c.lookupMetadata(ctx, dep)
	close(call.done)

	c.mu.Lock()
	delete(c.metaInflight, key)
	if call.err == nil {
		c.metaCache[key] = call.value
	}
	c.mu.Unlock()

	return call.value, call.err
}

func (c *Client) Vulnerabilities(ctx context.Context, dep model.Dependency) ([]Vulnerability, error) {
	key := dep.Key()
	c.mu.Lock()
	if cached, ok := c.vulnCache[key]; ok {
		c.mu.Unlock()
		return cached, nil
	}
	if inflight, ok := c.vulnInflight[key]; ok {
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-inflight.done:
			return inflight.value, inflight.err
		}
	}

	call := &vulnCall{done: make(chan struct{})}
	c.vulnInflight[key] = call
	c.mu.Unlock()

	call.value, call.err = c.lookupVulnerabilities(ctx, dep)
	close(call.done)

	c.mu.Lock()
	delete(c.vulnInflight, key)
	if call.err == nil {
		c.vulnCache[key] = call.value
	}
	c.mu.Unlock()

	return call.value, call.err
}

func (c *Client) lookupMetadata(ctx context.Context, dep model.Dependency) (PackageMetadata, error) {
	switch dep.Ecosystem {
	case model.EcosystemGo:
		return c.goMetadata(ctx, dep.Name)
	case model.EcosystemNPM:
		return c.npmMetadata(ctx, dep.Name, dep.ResolvedVersion)
	case model.EcosystemPyPI:
		return c.pypiMetadata(ctx, dep.Name)
	default:
		return PackageMetadata{}, fmt.Errorf("unsupported ecosystem %q", dep.Ecosystem)
	}
}

func (c *Client) lookupVulnerabilities(ctx context.Context, dep model.Dependency) ([]Vulnerability, error) {
	return c.osvVulnerabilities(ctx, dep)
}
