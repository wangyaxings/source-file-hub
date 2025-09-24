package config

import (
    "io/fs"
    "os"
    "path/filepath"
    "strconv"
    "errors"

    "gopkg.in/yaml.v3"
)

type TLSConfig struct {
    CertFile string `yaml:"cert_file"`
    KeyFile  string `yaml:"key_file"`
}

type ServerConfig struct {
    Host string    `yaml:"host"`
    Port int       `yaml:"port"`
    TLS  TLSConfig `yaml:"tls"`
}

type DatabaseConfig struct {
    Driver   string `yaml:"driver"`
    Host     string `yaml:"host"`
    Port     int    `yaml:"port"`
    Database string `yaml:"database"`
}

type SecurityConfig struct {
    // reserved for future (jwt, rate limiting, etc.)
}

type StorageConfig struct {
    // reserved for future
}

type ApplicationConfig struct {
    Version string `yaml:"version"`
}

type Config struct {
    Server   ServerConfig   `yaml:"server"`
    Database DatabaseConfig `yaml:"database"`
    Security SecurityConfig `yaml:"security"`
    Storage  StorageConfig  `yaml:"storage"`
    Application ApplicationConfig `yaml:"application"`
}

// Default returns a config populated with sensible defaults matching current behavior
func Default() *Config {
    return &Config{
        Server: ServerConfig{
            Host: "0.0.0.0",
            Port: 8443,
            TLS: TLSConfig{
                CertFile: "certs/server.crt",
                KeyFile:  "certs/server.key",
            },
        },
        Database: DatabaseConfig{
            Driver:   "sqlite",
            Database: "data/fileserver.db",
        },
        Application: ApplicationConfig{
            Version: "v1.0.0",
        },
    }
}

// Load attempts to read configs/app.yaml; if not present returns defaults.
func Load() *Config {
    cfg := Default()
    path := filepath.Join("configs", "app.yaml")
    b, err := os.ReadFile(path)
    if err != nil {
        // if not exists, return defaults
        if errorsIsNotExist(err) {
            return cfg
        }
        return cfg
    }
    _ = yaml.Unmarshal(b, cfg)

    // Environment overrides (non-fatal)
    if v := os.Getenv("SERVER_HOST"); v != "" {
        cfg.Server.Host = v
    }
    if v := os.Getenv("SERVER_PORT"); v != "" {
        if p, err := strconv.Atoi(v); err == nil { cfg.Server.Port = p }
    }
    if v := os.Getenv("DB_PATH"); v != "" { // backward compatible env
        cfg.Database.Database = v
    }
    if v := os.Getenv("DB_DRIVER"); v != "" {
        cfg.Database.Driver = v
    }
    return cfg
}

// helpers
func errorsIsNotExist(err error) bool {
    if err == nil { return false }
    if errors.Is(err, fs.ErrNotExist) { return true }
    return os.IsNotExist(err)
}
