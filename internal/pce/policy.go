package pce

import (
	"fmt"
	"log"
	"strings"

	"illumio/denyrules/internal/config"
)

const (
	activePolicyVersion = "active"
	draftPolicyVersion  = "draft"
)

// Ruleset represents a PCE rule set.
type Ruleset struct {
	Href   string         `json:"href"`
	Name   string         `json:"name"`
	Scopes [][]ScopeActor `json:"scopes"`
}

// Rule represents a PCE security rule.
type Rule struct {
	Href              string           `json:"href"`
	Enabled           bool             `json:"enabled"`
	Action            string           `json:"action,omitempty"` // "allow", "deny", or "drop"; omitted = "allow"
	Consumers         []ScopeActor     `json:"consumers"`
	Providers         []ScopeActor     `json:"providers"`
	IngressServices   []IngressService `json:"ingress_services"`
	UnscopedConsumers bool             `json:"unscoped_consumers"`
}

// IngressService is either a named service reference (Href set) or an inline port/proto.
type IngressService struct {
	Href     string `json:"href,omitempty"`
	Name     string `json:"name,omitempty"`
	Proto    *int   `json:"proto,omitempty"`
	Port     *int   `json:"port,omitempty"`
	ToPort   *int   `json:"to_port,omitempty"`
	ICMPType *int   `json:"icmp_type,omitempty"`
	ICMPCode *int   `json:"icmp_code,omitempty"`
}

// ListRulesets returns draft and active rulesets.
func ListRulesets(cfg *config.Config) ([]Ruleset, error) {
	c, err := New(cfg)
	if err != nil {
		return nil, err
	}
	var out []Ruleset
	for _, version := range []string{draftPolicyVersion, activePolicyVersion} {
		rs, err := fetchAllPages[Ruleset](c, c.OrgPath(fmt.Sprintf("sec_policy/%s/rule_sets", version)))
		if err != nil {
			return nil, fmt.Errorf("list %s rulesets: %w", version, err)
		}
		log.Printf("rulesets fetched from %s (%d items)", version, len(rs))
		out = append(out, rs...)
	}
	return out, nil
}

// FetchRules returns all sec_rules for the given ruleset href.
func FetchRules(cfg *config.Config, rulesetHref string) ([]Rule, error) {
	c, err := New(cfg)
	if err != nil {
		return nil, err
	}
	url := c.HrefURL(rulesetHref) + "/sec_rules"
	rules, err := fetchAllPages[Rule](c, url)
	if err != nil {
		return nil, fmt.Errorf("fetch rules for %s: %w", rulesetHref, err)
	}
	return rules, nil
}

// FetchDenyRules returns all deny_rules for the given ruleset href.
// Newer PCE versions expose deny rules as a dedicated child collection.
func FetchDenyRules(cfg *config.Config, rulesetHref string) ([]Rule, error) {
	c, err := New(cfg)
	if err != nil {
		return nil, err
	}
	url := c.HrefURL(rulesetHref) + "/deny_rules"
	rules, err := fetchAllPages[Rule](c, url)
	if err != nil {
		return nil, fmt.Errorf("fetch deny rules for %s: %w", rulesetHref, err)
	}
	for i := range rules {
		if rules[i].Action == "" {
			rules[i].Action = "deny"
		}
	}
	return rules, nil
}

// IsDenyRule returns true if the rule's action is deny or drop.
func IsDenyRule(r Rule) bool {
	a := strings.ToLower(r.Action)
	return a == "deny" || a == "drop" || a == "override_deny"
}

// EnforcementBoundary is an Illumio deny rule — a standalone policy object
// (not inside a ruleset) that blocks matching traffic.
// API: GET /orgs/{id}/sec_policy/{version}/enforcement_boundaries
type EnforcementBoundary struct {
	Href            string           `json:"href"`
	Name            string           `json:"name,omitempty"`
	Consumers       []ScopeActor     `json:"consumers"`
	Providers       []ScopeActor     `json:"providers"`
	IngressServices []IngressService `json:"ingress_services"`
}

// FetchEnforcementBoundaries returns active enforcement boundaries.
func FetchEnforcementBoundaries(cfg *config.Config) ([]EnforcementBoundary, error) {
	c, err := New(cfg)
	if err != nil {
		return nil, err
	}
	items, err := fetchAllPages[EnforcementBoundary](c, c.OrgPath(fmt.Sprintf("sec_policy/%s/enforcement_boundaries", activePolicyVersion)))
	if err != nil {
		return nil, fmt.Errorf("fetch %s enforcement boundaries: %w", activePolicyVersion, err)
	}
	log.Printf("enforcement boundaries fetched from %s (%d items)", activePolicyVersion, len(items))
	return items, nil
}

func canonicalPolicyHref(href string) string {
	href = strings.Replace(href, "/sec_policy/draft/", "/sec_policy/{version}/", 1)
	href = strings.Replace(href, "/sec_policy/active/", "/sec_policy/{version}/", 1)
	return href
}

func policyHrefVersion(href string) string {
	switch {
	case strings.Contains(href, "/sec_policy/draft/"):
		return draftPolicyVersion
	case strings.Contains(href, "/sec_policy/active/"):
		return activePolicyVersion
	default:
		return ""
	}
}
