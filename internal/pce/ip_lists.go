package pce

import (
	"fmt"
	"sync"
	"time"

	"illumio/denyrules/internal/config"
)

// IPList represents a named IP List in the PCE.
type IPList struct {
	Href     string    `json:"href"`
	Name     string    `json:"name"`
	IPRanges []IPRange `json:"ip_ranges"`
}

// IPRange is one entry in an IP List.
type IPRange struct {
	FromIP    string `json:"from_ip"`
	ToIP      string `json:"to_ip,omitempty"`
	Exclusion bool   `json:"exclusion,omitempty"`
}

var ipListCache = &struct {
	mu   sync.Mutex
	data []IPList
	ts   time.Time
}{}

// FetchIPLists returns all IP Lists, using the in-memory cache if fresh.
func FetchIPLists(cfg *config.Config, force bool) ([]IPList, error) {
	ipListCache.mu.Lock()
	defer ipListCache.mu.Unlock()

	if !force && ipListCache.data != nil && time.Since(ipListCache.ts) < cacheTTL {
		return ipListCache.data, nil
	}
	c, err := New(cfg)
	if err != nil {
		return nil, err
	}
	var lists []IPList
	for _, version := range []string{activePolicyVersion, draftPolicyVersion} {
		items, err := fetchAllPages[IPList](c, c.OrgPath("sec_policy/"+version+"/ip_lists"))
		if err != nil {
			return nil, fmt.Errorf("fetch %s ip lists: %w", version, err)
		}
		lists = append(lists, items...)
	}
	ipListCache.data = lists
	ipListCache.ts = time.Now()
	return lists, nil
}
