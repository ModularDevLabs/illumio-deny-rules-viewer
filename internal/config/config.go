package config

import (
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	PCEHost      string
	PCEPort      int
	PCEOrgID     int
	PCEAPIKey    string
	PCEAPISecret string
	PCETLSVerify bool
}

// Load reads .env then .env.local (local overrides), then OS env.
func Load() *Config {
	_ = godotenv.Load(".env")
	_ = godotenv.Overload(".env.local")

	return &Config{
		PCEHost:      getenv("PCE_HOST", ""),
		PCEPort:      getenvInt("PCE_PORT", 443),
		PCEOrgID:     getenvInt("PCE_ORG_ID", 1),
		PCEAPIKey:    getenv("PCE_API_KEY", ""),
		PCEAPISecret: getenv("PCE_API_SECRET", ""),
		PCETLSVerify: getenvBool("PCE_TLS_VERIFY", true),
	}
}

// Reload re-reads env files into an existing Config pointer in place.
func (c *Config) Reload() {
	_ = godotenv.Overload(".env.local")
	c.PCEHost = getenv("PCE_HOST", "")
	c.PCEPort = getenvInt("PCE_PORT", 443)
	c.PCEOrgID = getenvInt("PCE_ORG_ID", 1)
	c.PCEAPIKey = getenv("PCE_API_KEY", "")
	c.PCEAPISecret = getenv("PCE_API_SECRET", "")
	c.PCETLSVerify = getenvBool("PCE_TLS_VERIFY", true)
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
