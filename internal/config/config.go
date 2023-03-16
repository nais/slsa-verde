package config

type Config struct {
	IgnoreTLog         bool            `json:"ignore-tlog"`
	Issuer             string          `json:"issuer"`
	MetricsBindAddress string          `json:"bind-address"`
	LocalImage         bool            `json:"local-image"`
	LogLevel           string          `json:"log-level"`
	KeyRef             string          `json:"key-ref"`
	RekorURL           string          `json:"rekor-url"`
	Storage            DependencyTrack `json:"storage"`
	ProjectId          string          `json:"project-id"`
}

type DependencyTrack struct {
	SbomApi    string `json:"sbom-api"`
	SbomApiKey string `json:"sbom-api-key"`
}

func DefaultConfig() *Config {
	return &Config{
		MetricsBindAddress: "127.0.0.1:8080",
		LogLevel:           "info",
	}
}
