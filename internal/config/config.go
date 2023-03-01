package config

type Config struct {
	MetricsBindAddress string `json:"bind-address"`
	LogLevel           string `json:"log-level"`
	SbomApi            string `json:"sbom-api"`
	SbomApiKey         string `json:"sbom-api-key"`
}

func DefaultConfig() *Config {
	return &Config{
		MetricsBindAddress: "127.0.0.1:8080",
		LogLevel:           "info",
	}
}
