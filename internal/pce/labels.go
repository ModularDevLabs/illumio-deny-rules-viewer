package pce

import (
	"fmt"
	"sync"
	"time"

	"illumio/denyrules/internal/config"
)

const cacheTTL = 5 * time.Minute

// Label represents a PCE label.
type Label struct {
	Href  string `json:"href"`
	Key   string `json:"key"`
	Value string `json:"value"`
}

// LabelGroup represents a PCE label group.
type LabelGroup struct {
	Href string `json:"href"`
	Name string `json:"name"`
	Key  string `json:"key"`
}

var labelCache = &struct {
	mu      sync.Mutex
	labels  []Label
	groups  []LabelGroup
	labelTs time.Time
	groupTs time.Time
}{}

// FetchLabels returns all labels, using the in-memory cache if fresh.
func FetchLabels(cfg *config.Config, force bool) ([]Label, error) {
	labelCache.mu.Lock()
	defer labelCache.mu.Unlock()

	if !force && labelCache.labels != nil && time.Since(labelCache.labelTs) < cacheTTL {
		return labelCache.labels, nil
	}
	c, err := New(cfg)
	if err != nil {
		return nil, err
	}
	labels, err := fetchAllPages[Label](c, c.OrgPath("labels"))
	if err != nil {
		return nil, fmt.Errorf("fetch labels: %w", err)
	}
	labelCache.labels = labels
	labelCache.labelTs = time.Now()
	return labels, nil
}

// FetchLabelGroups returns all label groups, using the in-memory cache if fresh.
func FetchLabelGroups(cfg *config.Config, force bool) ([]LabelGroup, error) {
	labelCache.mu.Lock()
	defer labelCache.mu.Unlock()

	if !force && labelCache.groups != nil && time.Since(labelCache.groupTs) < cacheTTL {
		return labelCache.groups, nil
	}
	c, err := New(cfg)
	if err != nil {
		return nil, err
	}
	groups, err := fetchAllPages[LabelGroup](c, c.OrgPath("sec_policy/"+policyVersion+"/label_groups"))
	if err != nil {
		return nil, fmt.Errorf("fetch label groups: %w", err)
	}
	labelCache.groups = groups
	labelCache.groupTs = time.Now()
	return groups, nil
}
