package config

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"sort"
	"strconv"

	"github.com/joho/godotenv"
)

const profilesPath = ".pce-profiles.json"

type Config struct {
	ProfileName   string
	Profiles      []Profile
	ActiveProfile string
	PCEHost       string
	PCEPort       int
	PCEOrgID      int
	PCEAPIKey     string
	PCEAPISecret  string
	PCETLSVerify  bool
}

type Profile struct {
	Name         string `json:"name"`
	PCEHost      string `json:"pce_host"`
	PCEPort      int    `json:"pce_port"`
	PCEOrgID     int    `json:"pce_org_id"`
	PCEAPIKey    string `json:"pce_api_key"`
	PCEAPISecret string `json:"pce_api_secret"`
	PCETLSVerify bool   `json:"pce_tls_verify"`
}

type Store struct {
	ActiveProfile string    `json:"active_profile"`
	Profiles      []Profile `json:"profiles"`
}

// Load reads the JSON profile store, falling back to legacy env config.
func Load() *Config {
	store, _ := loadStore()
	return configFromStore(store)
}

// Reload re-reads profile data into an existing Config pointer.
func (c *Config) Reload() {
	*c = *Load()
}

func (c *Config) Profile(name string) (Profile, bool) {
	for _, p := range c.Profiles {
		if p.Name == name {
			return p, true
		}
	}
	return Profile{}, false
}

func (c *Config) SelectedProfile(name string) Profile {
	if name != "" {
		if p, ok := c.Profile(name); ok {
			return p
		}
	}
	if p, ok := c.Profile(c.ActiveProfile); ok {
		return p
	}
	return Profile{
		Name:         c.ActiveProfile,
		PCEHost:      c.PCEHost,
		PCEPort:      firstNonZero(c.PCEPort, 443),
		PCEOrgID:     firstNonZero(c.PCEOrgID, 1),
		PCEAPIKey:    c.PCEAPIKey,
		PCEAPISecret: c.PCEAPISecret,
		PCETLSVerify: defaultBool(c.PCETLSVerify, c.PCEHost == ""),
	}
}

func SaveProfile(p Profile, setActive bool) error {
	store, err := loadStore()
	if err != nil {
		return err
	}
	if p.Name == "" {
		return fmt.Errorf("profile name is required")
	}
	replaced := false
	for i := range store.Profiles {
		if store.Profiles[i].Name == p.Name {
			store.Profiles[i] = p
			replaced = true
			break
		}
	}
	if !replaced {
		store.Profiles = append(store.Profiles, p)
	}
	sort.Slice(store.Profiles, func(i, j int) bool {
		return store.Profiles[i].Name < store.Profiles[j].Name
	})
	if setActive || store.ActiveProfile == "" {
		store.ActiveProfile = p.Name
	}
	return writeStore(store)
}

func ActivateProfile(name string) error {
	store, err := loadStore()
	if err != nil {
		return err
	}
	for _, p := range store.Profiles {
		if p.Name == name {
			store.ActiveProfile = name
			return writeStore(store)
		}
	}
	return fmt.Errorf("profile %q not found", name)
}

func loadStore() (*Store, error) {
	if data, err := os.ReadFile(profilesPath); err == nil {
		var store Store
		if err := json.Unmarshal(data, &store); err != nil {
			return nil, fmt.Errorf("parse %s: %w", profilesPath, err)
		}
		normalizeStore(&store)
		return &store, nil
	}
	store := legacyStore()
	normalizeStore(store)
	return store, nil
}

func writeStore(store *Store) error {
	normalizeStore(store)
	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal store: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(profilesPath, data, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", profilesPath, err)
	}
	return nil
}

func normalizeStore(store *Store) {
	if store == nil {
		return
	}
	seen := make(map[string]struct{}, len(store.Profiles))
	filtered := make([]Profile, 0, len(store.Profiles))
	for _, p := range store.Profiles {
		if p.Name == "" {
			continue
		}
		if _, ok := seen[p.Name]; ok {
			continue
		}
		seen[p.Name] = struct{}{}
		if p.PCEPort == 0 {
			p.PCEPort = 443
		}
		if p.PCEOrgID == 0 {
			p.PCEOrgID = 1
		}
		filtered = append(filtered, p)
	}
	sort.Slice(filtered, func(i, j int) bool { return filtered[i].Name < filtered[j].Name })
	store.Profiles = filtered
	if store.ActiveProfile == "" && len(store.Profiles) > 0 {
		store.ActiveProfile = store.Profiles[0].Name
	}
	if store.ActiveProfile != "" && !slices.ContainsFunc(store.Profiles, func(p Profile) bool { return p.Name == store.ActiveProfile }) {
		if len(store.Profiles) > 0 {
			store.ActiveProfile = store.Profiles[0].Name
		} else {
			store.ActiveProfile = ""
		}
	}
}

func configFromStore(store *Store) *Config {
	cfg := &Config{}
	if store == nil {
		return cfg
	}
	cfg.Profiles = append(cfg.Profiles, store.Profiles...)
	cfg.ActiveProfile = store.ActiveProfile
	selected := cfg.SelectedProfile(store.ActiveProfile)
	cfg.ProfileName = selected.Name
	cfg.PCEHost = selected.PCEHost
	cfg.PCEPort = selected.PCEPort
	cfg.PCEOrgID = selected.PCEOrgID
	cfg.PCEAPIKey = selected.PCEAPIKey
	cfg.PCEAPISecret = selected.PCEAPISecret
	cfg.PCETLSVerify = selected.PCETLSVerify
	return cfg
}

func legacyStore() *Store {
	_ = godotenv.Load(".env")
	_ = godotenv.Overload(".env.local")
	host := getenv("PCE_HOST", "")
	if host == "" {
		return &Store{}
	}
	name := getenv("PCE_PROFILE_NAME", "default")
	return &Store{
		ActiveProfile: name,
		Profiles: []Profile{{
			Name:         name,
			PCEHost:      host,
			PCEPort:      getenvInt("PCE_PORT", 443),
			PCEOrgID:     getenvInt("PCE_ORG_ID", 1),
			PCEAPIKey:    getenv("PCE_API_KEY", ""),
			PCEAPISecret: getenv("PCE_API_SECRET", ""),
			PCETLSVerify: getenvBool("PCE_TLS_VERIFY", true),
		}},
	}
}

func firstNonZero(v, fallback int) int {
	if v != 0 {
		return v
	}
	return fallback
}

func defaultBool(v, fallback bool) bool {
	if v {
		return true
	}
	return fallback
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getenvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

func getenvBool(key string, fallback bool) bool {
	if v := os.Getenv(key); v != "" {
		switch v {
		case "false", "0", "no":
			return false
		default:
			return true
		}
	}
	return fallback
}
