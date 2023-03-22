package config

import (
	"errors"
	"github.com/mitchellh/mapstructure"
	log "github.com/sirupsen/logrus"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
	"sort"
	"strings"
)

type Config struct {
	Cosign             Cosign   `json:"cosign"`
	DevelopmentMode    bool     `json:"development-mode"`
	Identity           Identity `json:"identity"`
	LogLevel           string   `json:"log-level"`
	MetricsBindAddress string   `json:"metrics-address"`
	Storage            Storage  `json:"storage"`
}

type Cosign struct {
	IgnoreTLog bool   `json:"ignore-tlog"`
	KeyRef     string `json:"key-ref"`
	LocalImage bool   `json:"local-image"`
	RekorURL   string `json:"rekor-url"`
}

type Identity struct {
	Issuer    string `json:"issuer"`
	ProjectID string `json:"project-id"`
}

type Storage struct {
	Api    string `json:"api"`
	ApiKey string `json:"api-key"`
}

const (
	CosignIgnoreTLog  = "cosign.ignore-tlog"
	CosignKeyRef      = "cosign.key-ref"
	CosignLocalImage  = "cosign.local-image"
	CosignRekorURL    = "cosign.rekor-url"
	DevelopmentMode   = "development-mode"
	IdentityIssuer    = "identity.issuer"
	IdentityProjectID = "identity.project-id"
	LogLevel          = "log-level"
	MetricsAddress    = "metrics-address"
	StorageApi        = "storage.api"
	StorageApiKey     = "storage.api-key"
)

func init() {
	viper.SetEnvPrefix("PICANTE")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))

	// Read configuration file from working directory and/or /etc.
	// File formats supported include JSON, TOML, YAML, HCL, envfile and Java properties config files
	viper.SetConfigName("picante")
	viper.AddConfigPath(".")
	viper.AddConfigPath("/etc")

	flag.Bool(CosignIgnoreTLog, false, "Ignore transparency log")
	flag.Bool(CosignLocalImage, false, "Use local image")
	flag.Bool(DevelopmentMode, false, "Toggle for development mode.")
	flag.String(CosignKeyRef, "", "The key reference, empty for keyless attestation")
	flag.String(CosignRekorURL, "", "Rekor URL")
	flag.String(IdentityIssuer, "", "The issuer for keyless attestation")
	flag.String(IdentityProjectID, "", "The project ID for keyless attestation")
	flag.String(LogLevel, "", "Which log level to output")
	flag.String(MetricsAddress, "", "Bind address")
	flag.String(StorageApi, "", "Salsa storage API endpoint")
	flag.String(StorageApiKey, "", "SBOM API key")
}

func Load() (*Config, error) {
	var err error
	var cfg Config

	err = viper.ReadInConfig()
	if err != nil {
		if err.(viper.ConfigFileNotFoundError) != err {
			return nil, err
		}
	}

	flag.Parse()

	err = viper.BindPFlags(flag.CommandLine)
	if err != nil {
		return nil, err
	}

	err = viper.Unmarshal(&cfg, decoderHook)
	if err != nil {
		return nil, err
	}

	return &cfg, nil
}

func decoderHook(dc *mapstructure.DecoderConfig) {
	dc.TagName = "json"
	dc.ErrorUnused = false
}

func Print(redacted []string) {
	ok := func(key string) bool {
		for _, forbiddenKey := range redacted {
			if forbiddenKey == key {
				return false
			}
		}
		return true
	}

	var keys sort.StringSlice = viper.AllKeys()
	keys.Sort()
	for _, key := range keys {
		if ok(key) {
			log.Printf("%s: %s", key, viper.GetString(key))
		} else {
			log.Printf("%s: ***REDACTED***", key)
		}
	}
}

func Validate(required []string) error {
	present := func(key string) bool {
		for _, requiredKey := range required {
			if requiredKey == key {
				return len(viper.GetString(requiredKey)) > 0
			}
		}
		return true
	}
	var keys sort.StringSlice = viper.AllKeys()
	errs := make([]string, 0)

	keys.Sort()
	for _, key := range keys {
		if !present(key) {
			errs = append(errs, key)
		}
	}

	for _, key := range errs {
		log.Printf("required key '%s' not configured", key)
	}
	if len(errs) > 0 {
		return errors.New("missing configuration values")
	}
	return nil
}
