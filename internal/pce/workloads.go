package pce

import (
	"fmt"
	"sync"
	"time"

	"illumio/denyrules/internal/config"
)

// Workload is a labeled workload returned by the PCE.
type Workload struct {
	Href     string  `json:"href"`
	Name     string  `json:"name"`
	Hostname string  `json:"hostname"`
	Deleted  bool    `json:"deleted"`
	Online   *bool   `json:"online,omitempty"`
	Managed  *bool   `json:"managed,omitempty"`
	Labels   []Label `json:"labels"`
}

type LabelGroupDetail struct {
	Href        string    `json:"href"`
	Name        string    `json:"name"`
	Key         string    `json:"key"`
	Labels      []HrefRef `json:"labels"`
	LabelGroups []HrefRef `json:"label_groups"`
}

var workloadCache = &struct {
	mu   sync.Mutex
	data []Workload
	ts   time.Time
}{}

var labelGroupDetailCache = &struct {
	mu   sync.Mutex
	data map[string]LabelGroupDetail
	ts   map[string]time.Time
}{
	data: map[string]LabelGroupDetail{},
	ts:   map[string]time.Time{},
}

// FetchWorkloads returns all workloads, using the in-memory cache if fresh.
func FetchWorkloads(cfg *config.Config, force bool) ([]Workload, error) {
	workloadCache.mu.Lock()
	defer workloadCache.mu.Unlock()

	if !force && workloadCache.data != nil && time.Since(workloadCache.ts) < cacheTTL {
		return workloadCache.data, nil
	}
	c, err := New(cfg)
	if err != nil {
		return nil, err
	}
	items, err := fetchAllPages[Workload](c, c.OrgPath("workloads"))
	if err != nil {
		return nil, fmt.Errorf("fetch workloads: %w", err)
	}
	workloadCache.data = items
	workloadCache.ts = time.Now()
	return items, nil
}

// FetchLabelGroupDetail returns an individual label group, using cache if fresh.
func FetchLabelGroupDetail(cfg *config.Config, href string, force bool) (*LabelGroupDetail, error) {
	labelGroupDetailCache.mu.Lock()
	if !force {
		if item, ok := labelGroupDetailCache.data[href]; ok && time.Since(labelGroupDetailCache.ts[href]) < cacheTTL {
			labelGroupDetailCache.mu.Unlock()
			return &item, nil
		}
	}
	labelGroupDetailCache.mu.Unlock()

	c, err := New(cfg)
	if err != nil {
		return nil, err
	}
	var item LabelGroupDetail
	if err := c.Get(c.HrefURL(href), &item); err != nil {
		return nil, fmt.Errorf("fetch label group %s: %w", href, err)
	}

	labelGroupDetailCache.mu.Lock()
	labelGroupDetailCache.data[href] = item
	labelGroupDetailCache.ts[href] = time.Now()
	labelGroupDetailCache.mu.Unlock()
	return &item, nil
}
