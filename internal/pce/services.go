package pce

import (
	"fmt"
	"sync"
	"time"

	"illumio/denyrules/internal/config"
)

// PCEService represents a named service object in the PCE.
type PCEService struct {
	Href         string           `json:"href"`
	Name         string           `json:"name"`
	ServicePorts []PCEServicePort `json:"service_ports"`
}

// PCEServicePort is one port/proto entry within a named service.
type PCEServicePort struct {
	Proto    int  `json:"proto"`
	Port     *int `json:"port,omitempty"`
	ToPort   *int `json:"to_port,omitempty"`
	ICMPType *int `json:"icmp_type,omitempty"`
	ICMPCode *int `json:"icmp_code,omitempty"`
}

var svcCache = &struct {
	mu       sync.Mutex
	services []PCEService
	ts       time.Time
}{}

// FetchServices returns all named services, using the in-memory cache if fresh.
func FetchServices(cfg *config.Config, force bool) ([]PCEService, error) {
	svcCache.mu.Lock()
	defer svcCache.mu.Unlock()

	if !force && svcCache.services != nil && time.Since(svcCache.ts) < cacheTTL {
		return svcCache.services, nil
	}
	c, err := New(cfg)
	if err != nil {
		return nil, err
	}
	var svcs []PCEService
	for _, version := range []string{activePolicyVersion, draftPolicyVersion} {
		items, err := fetchAllPages[PCEService](c, c.OrgPath("sec_policy/"+version+"/services"))
		if err != nil {
			return nil, fmt.Errorf("fetch %s services: %w", version, err)
		}
		svcs = append(svcs, items...)
	}
	svcCache.services = svcs
	svcCache.ts = time.Now()
	return svcs, nil
}
