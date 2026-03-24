// Command deny-rules serves a web UI for viewing deny/drop rules from an Illumio PCE.
// All assets (templates, htmx) are embedded so the binary is fully self-contained.
package main

import (
	"bufio"
	"embed"
	"encoding/csv"
	"flag"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"illumio/denyrules/internal/config"
	"illumio/denyrules/internal/pce"
)

//go:embed templates static
var embedFS embed.FS

// ── Data types ───────────────────────────────────────────────────────────────

type pageData struct {
	Flash     string
	FlashType string
	Data      any
}

type indexPageData struct {
	PCEConfigured bool
	Cfg           *config.Config
}

type configPageData struct {
	Cfg             *config.Config
	Profiles        []config.Profile
	SelectedProfile config.Profile
	TestResult      *testResultData
}

type testResultData struct {
	OK      bool
	Message string
}

type resultsData struct {
	Boundaries []boundaryRow   // enforcement boundaries (primary deny rules)
	Rulesets   []rulesetResult // ruleset sec_rules with action=deny/drop (less common)
	Error      string
	Elapsed    string
	Total      int
}

type boundaryRow struct {
	Index        int
	Name         string
	Sources      []string
	Destinations []string
	Services     []string
}

type rulesetResult struct {
	ID        string
	Href      string
	Name      string
	Scope     string
	DenyRules []denyRuleRow
}

type denyRuleRow struct {
	Index        int
	Action       string
	ScopeType    string
	Sources      []string
	Destinations []string
	Services     []string
	Disabled     bool
}

type workloadRow struct {
	Name   string
	Labels []string
}

type rulesetWorkloadsData struct {
	RulesetName string
	Scope       string
	Count       int
	Workloads   []workloadRow
	Error       string
}

// ── Main ─────────────────────────────────────────────────────────────────────

func main() {
	addr := flag.String("addr", ":8082", "listen address")
	flag.Parse()

	cfg := config.Load()

	mux := http.NewServeMux()

	staticFS, _ := fs.Sub(embedFS, "static")
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))

	mux.HandleFunc("GET /{$}", indexHandler(cfg))
	mux.HandleFunc("GET /config", configGetHandler(cfg))
	mux.HandleFunc("POST /config", configPostHandler(cfg))
	mux.HandleFunc("POST /config/activate", configActivateHandler(cfg))
	mux.HandleFunc("POST /config/delete", configDeleteHandler(cfg))
	mux.HandleFunc("GET /config/test", configTestHandler(cfg))
	mux.HandleFunc("POST /api/fetch-rules", fetchRulesHandler(cfg))
	mux.HandleFunc("GET /api/ruleset-workloads", rulesetWorkloadsHandler(cfg))
	mux.HandleFunc("GET /api/export-csv", exportCSVHandler(cfg))

	log.Printf("Deny Rule Viewer listening on http://localhost%s", *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
}

// ── Handlers ─────────────────────────────────────────────────────────────────

func indexHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		renderPage(w, r, "templates/index.html", indexPageData{
			PCEConfigured: cfg.PCEHost != "",
			Cfg:           cfg,
		})
	}
}

func configGetHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		renderPage(w, r, "templates/config.html", configPageData{
			Cfg:             cfg,
			Profiles:        cfg.Profiles,
			SelectedProfile: cfg.SelectedProfile(r.URL.Query().Get("profile")),
		})
	}
}

func configPostHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			redirectWithFlash(w, r, "/config", "danger", "Invalid form")
			return
		}
		selected := cfg.SelectedProfile(r.FormValue("profile_name"))
		profile := config.Profile{
			Name:         strings.TrimSpace(r.FormValue("profile_name")),
			PCEHost:      strings.TrimSpace(r.FormValue("pce_host")),
			PCEPort:      atoiDefault(r.FormValue("pce_port"), 443),
			PCEOrgID:     atoiDefault(r.FormValue("pce_org_id"), 1),
			PCEAPIKey:    strings.TrimSpace(r.FormValue("pce_api_key")),
			PCEAPISecret: selected.PCEAPISecret,
			PCETLSVerify: strings.TrimSpace(r.FormValue("pce_tls_verify")) != "false",
		}
		if s := strings.TrimSpace(r.FormValue("pce_api_secret")); s != "" {
			profile.PCEAPISecret = s
		}
		if profile.Name == "" {
			redirectWithFlash(w, r, "/config", "danger", "Profile name is required")
			return
		}
		if err := config.SaveProfile(profile, true); err != nil {
			redirectWithFlash(w, r, "/config", "danger", "Save failed: "+err.Error())
			return
		}
		cfg.Reload()
		redirectWithFlash(w, r, "/config?profile="+url.QueryEscape(profile.Name), "success", "Profile saved and activated")
	}
}

func configActivateHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			redirectWithFlash(w, r, "/config", "danger", "Invalid form")
			return
		}
		name := strings.TrimSpace(r.FormValue("profile_name"))
		if name == "" {
			redirectWithFlash(w, r, "/config", "danger", "Profile name is required")
			return
		}
		if err := config.ActivateProfile(name); err != nil {
			redirectWithFlash(w, r, "/config", "danger", "Activate failed: "+err.Error())
			return
		}
		cfg.Reload()
		redirectWithFlash(w, r, "/config?profile="+url.QueryEscape(name), "success", "Active profile updated")
	}
}

func configDeleteHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			redirectWithFlash(w, r, "/config", "danger", "Invalid form")
			return
		}
		name := strings.TrimSpace(r.FormValue("profile_name"))
		if name == "" {
			redirectWithFlash(w, r, "/config", "danger", "Profile name is required")
			return
		}
		if err := config.DeleteProfile(name); err != nil {
			redirectWithFlash(w, r, "/config", "danger", "Delete failed: "+err.Error())
			return
		}
		cfg.Reload()
		redirectWithFlash(w, r, "/config", "success", "Profile deleted")
	}
}

func configTestHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		profile := cfg.SelectedProfile(r.URL.Query().Get("profile"))
		err := pce.TestConnection(configForProfile(profile, cfg))
		td := &testResultData{OK: err == nil, Message: "Connected successfully."}
		if err != nil {
			td.Message = err.Error()
		}
		renderPartial(w, "templates/partials/test_result.html", td)
	}
}

func fetchRulesHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		data, err := buildResultsData(cfg)
		if err != nil {
			data = &resultsData{Error: err.Error()}
		} else {
			data.Elapsed = time.Since(start).Round(time.Millisecond).String()
		}
		renderPartial(w, "templates/partials/results.html", data)
	}
}

func exportCSVHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data, err := buildResultsData(cfg)
		if err != nil {
			http.Error(w, "fetch failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", `attachment; filename="deny-rules.csv"`)
		cw := csv.NewWriter(w)
		_ = cw.Write([]string{"Type", "Container", "Scope", "Rule #", "Action", "Sources", "Destinations", "Services", "Enabled"})
		for _, boundary := range data.Boundaries {
			_ = cw.Write([]string{
				"Enforcement Boundary",
				sanitizeCSVField(boundary.Name),
				"",
				fmt.Sprintf("%d", boundary.Index),
				"DENY",
				sanitizeCSVField(strings.Join(boundary.Sources, "; ")),
				sanitizeCSVField(strings.Join(boundary.Destinations, "; ")),
				sanitizeCSVField(strings.Join(boundary.Services, "; ")),
				"true",
			})
		}
		for _, rs := range data.Rulesets {
			for _, rule := range rs.DenyRules {
				enabled := "true"
				if rule.Disabled {
					enabled = "false"
				}
				_ = cw.Write([]string{
					"Ruleset",
					sanitizeCSVField(rs.Name),
					sanitizeCSVField(rule.ScopeType),
					fmt.Sprintf("%d", rule.Index),
					sanitizeCSVField(rule.Action),
					sanitizeCSVField(strings.Join(rule.Sources, "; ")),
					sanitizeCSVField(strings.Join(rule.Destinations, "; ")),
					sanitizeCSVField(strings.Join(rule.Services, "; ")),
					enabled,
				})
			}
		}
		cw.Flush()
	}
}

func rulesetWorkloadsHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		href := strings.TrimSpace(r.URL.Query().Get("href"))
		if href == "" {
			renderPartial(w, "templates/partials/ruleset_workloads.html", &rulesetWorkloadsData{
				Error: "Missing ruleset href",
			})
			return
		}

		rulesets, err := pce.ListRulesets(cfg)
		if err != nil {
			renderPartial(w, "templates/partials/ruleset_workloads.html", &rulesetWorkloadsData{
				Error: "List rulesets failed: " + err.Error(),
			})
			return
		}
		var match *pce.Ruleset
		for i := range rulesets {
			if rulesets[i].Href == href {
				match = &rulesets[i]
				break
			}
		}
		if match == nil {
			renderPartial(w, "templates/partials/ruleset_workloads.html", &rulesetWorkloadsData{
				Error: "Ruleset not found in active policy",
			})
			return
		}

		data, err := buildRulesetWorkloadsData(cfg, *match)
		if err != nil {
			data = &rulesetWorkloadsData{
				RulesetName: match.Name,
				Scope:       matchScopeDisplay(*match, cfg),
				Error:       err.Error(),
			}
		}
		renderPartial(w, "templates/partials/ruleset_workloads.html", data)
	}
}

// ── Business logic ────────────────────────────────────────────────────────────

func buildResultsData(cfg *config.Config) (*resultsData, error) {
	type lr[T any] struct {
		v   T
		err error
	}
	lCh := make(chan lr[[]pce.Label], 1)
	gCh := make(chan lr[[]pce.LabelGroup], 1)
	iCh := make(chan lr[[]pce.IPList], 1)
	sCh := make(chan lr[[]pce.PCEService], 1)

	go func() { v, e := pce.FetchLabels(cfg, false); lCh <- lr[[]pce.Label]{v, e} }()
	go func() { v, e := pce.FetchLabelGroups(cfg, false); gCh <- lr[[]pce.LabelGroup]{v, e} }()
	go func() { v, e := pce.FetchIPLists(cfg, false); iCh <- lr[[]pce.IPList]{v, e} }()
	go func() { v, e := pce.FetchServices(cfg, false); sCh <- lr[[]pce.PCEService]{v, e} }()

	lRes, gRes, iRes, sRes := <-lCh, <-gCh, <-iCh, <-sCh
	for _, pair := range []struct {
		name string
		err  error
	}{
		{"labels", lRes.err},
		{"label groups", gRes.err},
		{"ip lists", iRes.err},
		{"services", sRes.err},
	} {
		if pair.err != nil {
			return nil, fmt.Errorf("fetch %s: %w", pair.name, pair.err)
		}
	}

	labelMap := make(map[string]string, len(lRes.v))
	for _, l := range lRes.v {
		labelMap[l.Href] = l.Key + "=" + l.Value
	}
	groupMap := make(map[string]string, len(gRes.v))
	for _, g := range gRes.v {
		groupMap[g.Href] = g.Name
	}
	ipListMap := make(map[string]string, len(iRes.v))
	for _, ip := range iRes.v {
		ipListMap[ip.Href] = ip.Name
	}
	svcMap := make(map[string]string, len(sRes.v))
	for _, s := range sRes.v {
		svcMap[s.Href] = formatNamedService(s)
	}

	// ── Enforcement Boundaries (primary deny rules) ───────────────────────
	var boundaryRows []boundaryRow
	boundaries, ebErr := pce.FetchEnforcementBoundaries(cfg)
	if ebErr != nil {
		log.Printf("WARN: %v", ebErr)
	}
	for i, eb := range boundaries {
		name := eb.Name
		if name == "" {
			name = fmt.Sprintf("Boundary %d", i+1)
		}
		boundaryRows = append(boundaryRows, boundaryRow{
			Index:        i + 1,
			Name:         name,
			Sources:      resolveActors(eb.Consumers, labelMap, groupMap, ipListMap),
			Destinations: resolveActors(eb.Providers, labelMap, groupMap, ipListMap),
			Services:     resolveServices(eb.IngressServices, svcMap),
		})
	}

	// ── Ruleset sec_rules with action=deny/drop (newer PCE versions) ──────
	rulesets, err := pce.ListRulesets(cfg)
	if err != nil {
		return nil, fmt.Errorf("list rulesets: %w", err)
	}
	rsByCanonical := make(map[string]*rulesetResult)
	for _, rs := range rulesets {
		rules, err := pce.FetchRules(cfg, rs.Href)
		if err != nil {
			log.Printf("WARN: fetch rules for %q: %v", rs.Name, err)
			continue
		}
		denyRules, err := pce.FetchDenyRules(cfg, rs.Href)
		if err != nil {
			if strings.Contains(err.Error(), "PCE returned 404") {
				log.Printf("INFO: deny_rules not available for %q", rs.Name)
			} else {
				log.Printf("WARN: fetch deny rules for %q: %v", rs.Name, err)
			}
		} else {
			rules = append(rules, denyRules...)
		}
		var rows []denyRuleRow
		for i, r := range rules {
			if !pce.IsDenyRule(r) {
				continue
			}
			rows = append(rows, denyRuleRow{
				Index:        i + 1,
				Action:       strings.ToUpper(r.Action),
				ScopeType:    ruleScopeType(r),
				Sources:      resolveRuleConsumers(r, labelMap, groupMap, ipListMap),
				Destinations: resolveActors(r.Providers, labelMap, groupMap, ipListMap),
				Services:     resolveServices(r.IngressServices, svcMap),
				Disabled:     !r.Enabled,
			})
		}
		if len(rows) == 0 {
			continue
		}
		key := canonicalRulesetKey(rs)
		existing := rsByCanonical[key]
		if existing == nil {
			rsByCanonical[key] = &rulesetResult{
				ID:        fmt.Sprintf("ruleset-%d", len(rsByCanonical)+1),
				Href:      rs.Href,
				Name:      rs.Name,
				Scope:     formatScopes(rs.Scopes, labelMap, groupMap),
				DenyRules: append([]denyRuleRow(nil), rows...),
			}
			continue
		}
		existing.DenyRules = mergeDenyRuleRows(existing.DenyRules, rows)
		if existing.Scope == "" {
			existing.Scope = formatScopes(rs.Scopes, labelMap, groupMap)
		}
	}
	rsResults := make([]rulesetResult, 0, len(rsByCanonical))
	for _, rs := range rsByCanonical {
		rsResults = append(rsResults, *rs)
	}
	sort.Slice(rsResults, func(i, j int) bool {
		return strings.ToLower(rsResults[i].Name) < strings.ToLower(rsResults[j].Name)
	})

	total := len(boundaryRows)
	for _, rs := range rsResults {
		total += len(rs.DenyRules)
	}
	return &resultsData{
		Boundaries: boundaryRows,
		Rulesets:   rsResults,
		Total:      total,
	}, nil
}

func buildRulesetWorkloadsData(cfg *config.Config, rs pce.Ruleset) (*rulesetWorkloadsData, error) {
	type lr[T any] struct {
		v   T
		err error
	}
	lCh := make(chan lr[[]pce.Label], 1)
	gCh := make(chan lr[[]pce.LabelGroup], 1)
	wCh := make(chan lr[[]pce.Workload], 1)

	go func() { v, e := pce.FetchLabels(cfg, false); lCh <- lr[[]pce.Label]{v, e} }()
	go func() { v, e := pce.FetchLabelGroups(cfg, false); gCh <- lr[[]pce.LabelGroup]{v, e} }()
	go func() { v, e := pce.FetchWorkloads(cfg, false); wCh <- lr[[]pce.Workload]{v, e} }()

	lRes, gRes, wRes := <-lCh, <-gCh, <-wCh
	for _, pair := range []struct {
		name string
		err  error
	}{
		{"labels", lRes.err},
		{"label groups", gRes.err},
		{"workloads", wRes.err},
	} {
		if pair.err != nil {
			return nil, fmt.Errorf("fetch %s: %w", pair.name, pair.err)
		}
	}

	labelMap := make(map[string]string, len(lRes.v))
	for _, l := range lRes.v {
		labelMap[l.Href] = l.Key + "=" + l.Value
	}
	groupMap := make(map[string]string, len(gRes.v))
	for _, g := range gRes.v {
		groupMap[g.Href] = g.Name
	}

	matcher := newScopeMatcher(cfg)
	rows := make([]workloadRow, 0)
	for _, wl := range wRes.v {
		if wl.Deleted || !matcher.matchesRulesetScope(rs.Scopes, wl) {
			continue
		}
		labels := make([]string, 0, len(wl.Labels))
		for _, l := range wl.Labels {
			if name, ok := labelMap[l.Href]; ok {
				labels = append(labels, name)
			} else if l.Key != "" || l.Value != "" {
				labels = append(labels, l.Key+"="+l.Value)
			} else {
				labels = append(labels, l.Href)
			}
		}
		sort.Strings(labels)
		name := wl.Hostname
		if name == "" {
			name = wl.Name
		}
		if name == "" {
			name = wl.Href
		}
		rows = append(rows, workloadRow{Name: name, Labels: labels})
	}
	sort.Slice(rows, func(i, j int) bool {
		return strings.ToLower(rows[i].Name) < strings.ToLower(rows[j].Name)
	})
	return &rulesetWorkloadsData{
		RulesetName: rs.Name,
		Scope:       formatScopes(rs.Scopes, labelMap, groupMap),
		Count:       len(rows),
		Workloads:   rows,
	}, nil
}

// ── Actor / service resolution ────────────────────────────────────────────────

func resolveActors(actors []pce.ScopeActor, labelMap, groupMap, ipListMap map[string]string) []string {
	out := make([]string, 0, len(actors))
	for _, a := range actors {
		value := ""
		switch {
		case a.Actors != "":
			if a.Actors == "ams" {
				value = "All Workloads"
			} else {
				value = a.Actors
			}
		case a.Label != nil:
			if n, ok := labelMap[a.Label.Href]; ok {
				value = n
			} else if a.Label.Name != "" {
				value = a.Label.Name
			} else {
				value = a.Label.Href
			}
		case a.LabelGroup != nil:
			if n, ok := groupMap[a.LabelGroup.Href]; ok {
				value = "LG: " + n
			} else if a.LabelGroup.Name != "" {
				value = "LG: " + a.LabelGroup.Name
			} else {
				value = a.LabelGroup.Href
			}
		case a.IPList != nil:
			if n, ok := ipListMap[a.IPList.Href]; ok {
				value = n
			} else if a.IPList.Name != "" {
				value = a.IPList.Name
			} else {
				value = a.IPList.Href
			}
		case a.Workload != nil:
			value = namedHref("Workload", a.Workload)
		case a.VirtualService != nil:
			value = namedHref("Virtual Service", a.VirtualService)
		case a.VirtualServer != nil:
			value = namedHref("Virtual Server", a.VirtualServer)
		}
		if value == "" {
			continue
		}
		if a.Exclusion {
			value = "Except: " + value
		}
		out = append(out, value)
	}
	if len(out) == 0 {
		return []string{"(none)"}
	}
	return out
}

func resolveRuleConsumers(r pce.Rule, labelMap, groupMap, ipListMap map[string]string) []string {
	resolved := resolveActors(r.Consumers, labelMap, groupMap, ipListMap)
	if len(r.Consumers) > 0 && !isNoneOnly(resolved) {
		return resolved
	}
	if r.UnscopedConsumers {
		return []string{"All Workloads"}
	}
	return resolved
}

func namedHref(kind string, ref *pce.HrefRef) string {
	if ref == nil {
		return ""
	}
	if ref.Name != "" {
		return kind + ": " + ref.Name
	}
	return kind + ": " + ref.Href
}

func formatScopes(scopes [][]pce.ScopeActor, labelMap, groupMap map[string]string) string {
	rows := make([]string, 0, len(scopes))
	for _, row := range scopes {
		parts := resolveActors(row, labelMap, groupMap, nil)
		rows = append(rows, strings.Join(parts, ", "))
	}
	return strings.Join(rows, " | ")
}

func resolveServices(services []pce.IngressService, svcMap map[string]string) []string {
	if len(services) == 0 {
		return []string{"All Services"}
	}
	out := make([]string, 0, len(services))
	for _, s := range services {
		if s.Href != "" {
			if n, ok := svcMap[s.Href]; ok {
				out = append(out, n)
			} else if s.Name != "" {
				out = append(out, s.Name)
			} else {
				out = append(out, s.Href)
			}
			continue
		}
		proto := 0
		if s.Proto != nil {
			proto = *s.Proto
		}
		pName := protoStr(proto)
		switch proto {
		case 1, 58: // ICMP, ICMPv6
			if s.ICMPType != nil {
				if s.ICMPCode != nil {
					out = append(out, fmt.Sprintf("%s t=%d c=%d", pName, *s.ICMPType, *s.ICMPCode))
				} else {
					out = append(out, fmt.Sprintf("%s t=%d", pName, *s.ICMPType))
				}
			} else {
				out = append(out, pName)
			}
		default:
			if s.Port != nil {
				if s.ToPort != nil && *s.ToPort != *s.Port {
					out = append(out, fmt.Sprintf("%s/%d-%d", pName, *s.Port, *s.ToPort))
				} else {
					out = append(out, fmt.Sprintf("%s/%d", pName, *s.Port))
				}
			} else {
				out = append(out, pName)
			}
		}
	}
	return out
}

func formatNamedService(s pce.PCEService) string {
	if len(s.ServicePorts) == 0 {
		if s.Name != "" {
			return s.Name
		}
		return s.Href
	}
	parts := make([]string, 0, len(s.ServicePorts))
	for _, sp := range s.ServicePorts {
		parts = append(parts, formatNamedServicePort(sp))
	}
	label := s.Name
	if label == "" {
		label = s.Href
	}
	return fmt.Sprintf("%s (%s)", label, strings.Join(parts, ", "))
}

func formatNamedServicePort(sp pce.PCEServicePort) string {
	pName := protoStr(sp.Proto)
	switch sp.Proto {
	case 1, 58:
		if sp.ICMPType != nil {
			if sp.ICMPCode != nil {
				return fmt.Sprintf("%s t=%d c=%d", pName, *sp.ICMPType, *sp.ICMPCode)
			}
			return fmt.Sprintf("%s t=%d", pName, *sp.ICMPType)
		}
		return pName
	default:
		if sp.Port == nil {
			return pName
		}
		if sp.ToPort != nil && *sp.ToPort != *sp.Port {
			return fmt.Sprintf("%s/%d-%d", pName, *sp.Port, *sp.ToPort)
		}
		return fmt.Sprintf("%s/%d", pName, *sp.Port)
	}
}

func protoStr(proto int) string {
	switch proto {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 58:
		return "ICMPv6"
	default:
		return fmt.Sprintf("proto-%d", proto)
	}
}

// ── Template rendering ────────────────────────────────────────────────────────

var tmplFuncs = template.FuncMap{
	"hasPrefix": strings.HasPrefix,
}

func renderPage(w http.ResponseWriter, r *http.Request, pageTmpl string, data any) {
	files := []string{"templates/base.html", pageTmpl}
	tmpl, err := template.New("").Funcs(tmplFuncs).ParseFS(embedFS, files...)
	if err != nil {
		http.Error(w, "template error: "+err.Error(), http.StatusInternalServerError)
		log.Printf("template parse error (%s): %v", pageTmpl, err)
		return
	}
	pd := pageData{
		Flash:     r.URL.Query().Get("flash"),
		FlashType: r.URL.Query().Get("flash_type"),
		Data:      data,
	}
	if pd.FlashType == "" && pd.Flash != "" {
		pd.FlashType = "info"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, "base", pd); err != nil {
		log.Printf("template execute error (%s): %v", pageTmpl, err)
	}
}

func renderPartial(w http.ResponseWriter, partialTmpl string, data any) {
	tmpl, err := template.New("").Funcs(tmplFuncs).ParseFS(embedFS, partialTmpl)
	if err != nil {
		http.Error(w, "template error: "+err.Error(), http.StatusInternalServerError)
		log.Printf("partial parse error (%s): %v", partialTmpl, err)
		return
	}
	name := path.Base(partialTmpl)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, name, data); err != nil {
		log.Printf("partial execute error (%s): %v", partialTmpl, err)
	}
}

func redirectWithFlash(w http.ResponseWriter, r *http.Request, basePath, flashType, flash string) {
	q := url.Values{}
	q.Set("flash", flash)
	q.Set("flash_type", flashType)
	sep := "?"
	if strings.Contains(basePath, "?") {
		sep = "&"
	}
	http.Redirect(w, r, basePath+sep+q.Encode(), http.StatusFound)
}

func configForProfile(profile config.Profile, current *config.Config) *config.Config {
	return &config.Config{
		ProfileName:   profile.Name,
		Profiles:      current.Profiles,
		ActiveProfile: current.ActiveProfile,
		PCEHost:       profile.PCEHost,
		PCEPort:       profile.PCEPort,
		PCEOrgID:      profile.PCEOrgID,
		PCEAPIKey:     profile.PCEAPIKey,
		PCEAPISecret:  profile.PCEAPISecret,
		PCETLSVerify:  profile.PCETLSVerify,
	}
}

func atoiDefault(v string, fallback int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
		return n
	}
	return fallback
}

// ── .env.local helpers ────────────────────────────────────────────────────────

func writeEnvLocal(fields map[string]string) error {
	const envPath = ".env.local"
	existing := map[string]string{}
	if f, err := os.Open(envPath); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := sc.Text()
			if k, v, ok := strings.Cut(line, "="); ok && !strings.HasPrefix(k, "#") {
				existing[strings.TrimSpace(k)] = strings.TrimSpace(v)
			}
		}
		f.Close()
	}
	for k, v := range fields {
		if v != "" {
			existing[k] = v
		}
	}
	f, err := os.Create(envPath)
	if err != nil {
		return fmt.Errorf("create .env.local: %w", err)
	}
	defer f.Close()
	keys := make([]string, 0, len(existing))
	for k := range existing {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(f, "%s=%s\n", k, strconv.Quote(existing[k]))
	}
	return nil
}

func sanitizeCSVField(v string) string {
	if v == "" {
		return v
	}
	switch v[0] {
	case '=', '+', '-', '@':
		return "'" + v
	default:
		return v
	}
}

func canonicalRulesetKey(rs pce.Ruleset) string {
	if rs.Href == "" {
		return rs.Name + "|" + formatScopes(rs.Scopes, nil, nil)
	}
	return strings.Replace(strings.Replace(rs.Href, "/sec_policy/draft/", "/sec_policy/{version}/", 1), "/sec_policy/active/", "/sec_policy/{version}/", 1)
}

func mergeDenyRuleRows(existing, incoming []denyRuleRow) []denyRuleRow {
	seen := make(map[string]struct{}, len(existing))
	for _, row := range existing {
		seen[denyRuleKey(row)] = struct{}{}
	}
	for _, row := range incoming {
		key := denyRuleKey(row)
		if _, ok := seen[key]; ok {
			continue
		}
		existing = append(existing, row)
		seen[key] = struct{}{}
	}
	for i := range existing {
		existing[i].Index = i + 1
	}
	return existing
}

func denyRuleKey(row denyRuleRow) string {
	return strings.Join([]string{
		row.Action,
		row.ScopeType,
		strings.Join(row.Sources, "\x1f"),
		strings.Join(row.Destinations, "\x1f"),
		strings.Join(row.Services, "\x1f"),
		strconv.FormatBool(row.Disabled),
	}, "\x1e")
}

func isNoneOnly(values []string) bool {
	return len(values) == 1 && values[0] == "(none)"
}

func ruleScopeType(r pce.Rule) string {
	if r.UnscopedConsumers {
		return "Extrascope"
	}
	return "Intrascope"
}

func matchScopeDisplay(rs pce.Ruleset, cfg *config.Config) string {
	labels, err := pce.FetchLabels(cfg, false)
	if err != nil {
		return ""
	}
	groups, err := pce.FetchLabelGroups(cfg, false)
	if err != nil {
		return ""
	}
	labelMap := make(map[string]string, len(labels))
	for _, l := range labels {
		labelMap[l.Href] = l.Key + "=" + l.Value
	}
	groupMap := make(map[string]string, len(groups))
	for _, g := range groups {
		groupMap[g.Href] = g.Name
	}
	return formatScopes(rs.Scopes, labelMap, groupMap)
}

type scopeMatcher struct {
	cfg           *config.Config
	labelGroupSet map[string]map[string]struct{}
}

func newScopeMatcher(cfg *config.Config) *scopeMatcher {
	return &scopeMatcher{
		cfg:           cfg,
		labelGroupSet: map[string]map[string]struct{}{},
	}
}

func (m *scopeMatcher) matchesRulesetScope(scopes [][]pce.ScopeActor, wl pce.Workload) bool {
	if len(scopes) == 0 {
		return true
	}
	for _, row := range scopes {
		if m.matchesScopeRow(row, wl) {
			return true
		}
	}
	return false
}

func (m *scopeMatcher) matchesScopeRow(row []pce.ScopeActor, wl pce.Workload) bool {
	for _, actor := range row {
		if !m.matchesActor(actor, wl) {
			return false
		}
	}
	return true
}

func (m *scopeMatcher) matchesActor(actor pce.ScopeActor, wl pce.Workload) bool {
	matched := false
	switch {
	case actor.Actors == "ams":
		matched = true
	case actor.Label != nil:
		matched = workloadHasLabel(wl, actor.Label.Href)
	case actor.LabelGroup != nil:
		matched = m.workloadInLabelGroup(wl, actor.LabelGroup.Href)
	case actor.Workload != nil:
		matched = wl.Href == actor.Workload.Href
	}
	if actor.Exclusion {
		return !matched
	}
	return matched
}

func (m *scopeMatcher) workloadInLabelGroup(wl pce.Workload, href string) bool {
	labels, err := m.expandLabelGroup(href, map[string]bool{})
	if err != nil {
		log.Printf("WARN: expand label group %s: %v", href, err)
		return false
	}
	for _, l := range wl.Labels {
		if _, ok := labels[l.Href]; ok {
			return true
		}
	}
	return false
}

func (m *scopeMatcher) expandLabelGroup(href string, seen map[string]bool) (map[string]struct{}, error) {
	if labels, ok := m.labelGroupSet[href]; ok {
		return labels, nil
	}
	if seen[href] {
		return map[string]struct{}{}, nil
	}
	seen[href] = true

	detail, err := pce.FetchLabelGroupDetail(m.cfg, href, false)
	if err != nil {
		return nil, err
	}
	labels := make(map[string]struct{}, len(detail.Labels))
	for _, l := range detail.Labels {
		labels[l.Href] = struct{}{}
	}
	for _, child := range detail.LabelGroups {
		childLabels, err := m.expandLabelGroup(child.Href, seen)
		if err != nil {
			return nil, err
		}
		for href := range childLabels {
			labels[href] = struct{}{}
		}
	}
	m.labelGroupSet[href] = labels
	return labels, nil
}

func workloadHasLabel(wl pce.Workload, href string) bool {
	for _, l := range wl.Labels {
		if l.Href == href {
			return true
		}
	}
	return false
}
