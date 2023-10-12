package config

import (
	"fmt"
	"sort"
	"strings"

	"github.com/mitchellh/mapstructure"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	log "github.com/sirupsen/logrus"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
)

type Cosign struct {
	IgnoreTLog bool   `json:"ignore-tlog"`
	KeyRef     string `json:"key-ref"`
	LocalImage bool   `json:"local-image"`
	RekorURL   string `json:"rekor-url"`
}

type Label struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type GitHub struct {
	Organizations []string `json:"organizations"`
}

type Features struct {
	LabelSelectors []Label `json:"label-selectors"`
}

type Identity struct {
	Issuer        string `json:"issuer"`
	IssuerRegExp  string `json:"issuer-reg-exp"`
	Subject       string `json:"subject"`
	SubjectRegExp string `json:"subject-reg-exp"`
}

type Storage struct {
	Api      string `json:"api"`
	Username string `json:"username"`
	Password string `json:"password"`
	Team     string `json:"team"`
}

type TeamIdentity struct {
	Domain string `json:"domain"`
	Issuer string `json:"issuer"`
}

type Config struct {
	Cluster                   string       `json:"cluster"`
	Cosign                    Cosign       `json:"cosign"`
	DevelopmentMode           bool         `json:"development-mode"`
	Features                  Features     `json:"features"`
	GitHub                    GitHub       `json:"github"`
	LogLevel                  string       `json:"log-level"`
	MetricsBindAddress        string       `json:"metrics-address"`
	PreConfiguredSaIdentities []Identity   `json:"identities"`
	Storage                   Storage      `json:"storage"`
	TeamIdentity              TeamIdentity `json:"teamIdentity"`
}

const (
	Cluster                = "cluster"
	CosignIgnoreTLog       = "cosign.ignore-tlog"
	CosignKeyRef           = "cosign.key-ref"
	CosignLocalImage       = "cosign.local-image"
	CosignRekorURL         = "cosign.rekor-url"
	DevelopmentMode        = "development-mode"
	FeaturesLabelSelectors = "features.label-selectors"
	GitHubOrganizations    = "github.organizations"
	Identities             = "identities"
	LogLevel               = "log-level"
	MetricsAddress         = "metrics-address"
	StorageApi             = "storage.api"
	StorageUsername        = "storage.username"
	StoragePassword        = "storage.password"
	StorageTeam            = "storage.team"
	TeamIdentityDomain     = "teamIdentity.domain"
	TeamIdentityIssuer     = "teamIdentity.issuer"
)

func init() {
	viper.SetEnvPrefix("PICANTE")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))

	// Read configuration file from working directory and/or /etc.
	// File formats supported include JSON, TOML, YAML, HCL, envfile and Java properties config files
	viper.SetConfigName("picante")
	viper.AddConfigPath(".")
	viper.AddConfigPath("/etc/picante")

	flag.String(Cluster, "", "Cluster name, e.g. dev")
	flag.Bool(CosignIgnoreTLog, false, "Ignore transparency log")
	flag.Bool(CosignLocalImage, false, "Use local image")
	flag.Bool(DevelopmentMode, false, "Toggle for development mode.")
	flag.String(CosignKeyRef, "", "The key reference, empty for keyless attestation")
	flag.String(CosignRekorURL, "https://rekor.sigstore.dev", "Rekor URL")
	flag.String(LogLevel, "info", "Which log level to output")
	flag.String(MetricsAddress, ":8080", "Bind address")
	flag.String(StorageApi, "", "Salsa storage API endpoint")
	flag.String(StoragePassword, "", "Salsa storage password")
	flag.String(StorageTeam, "", "Salsa storage team")
	flag.String(StorageUsername, "", "Salsa storage username")
	flag.String(TeamIdentityDomain, "", "Domain for team identity")
	flag.String(TeamIdentityIssuer, "", "Issuer for team identity")
	flag.StringSlice(FeaturesLabelSelectors, []string{}, "List of labels to filter on")
	flag.StringSlice(Identities, []string{}, "List of identities to filter on")
	flag.StringSlice(GitHubOrganizations, []string{}, "List of GitHub organizations to filter on")
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
	log.Infof("Configuration file in use: %s", viper.ConfigFileUsed())
	for _, key := range keys {
		if !ok(key) {
			log.Infof("%s: ***REDACTED***", key)
		} else {
			switch viper.Get(key).(type) {
			case []interface{}:
				for _, value := range viper.Get(key).([]interface{}) {
					switch v := value.(type) {
					case map[string]interface{}:
						for k, v := range v {
							log.Infof("%s.%s: %s", key, k, v)
						}
					default:
						log.Infof("%s: %s", key, value)
					}
				}
			default:
				log.Infof("%s: %s", key, viper.GetString(key))

			}
		}
	}
}

func Validate(required []string) error {
	present := func(key string) bool {
		for _, requiredKey := range required {
			if requiredKey == key {
				return len(viper.GetString(requiredKey)) > 0 || len(viper.GetStringSlice(requiredKey)) > 0
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
		log.Infof("required key '%s' not configured", key)
	}
	if len(errs) > 0 {
		return fmt.Errorf("missing configuration values")
	}
	return nil
}

func (c *Config) GetLabelSelectors() string {
	var labelSelector string
	if len(c.Features.LabelSelectors) == 0 {
		return labelSelector
	}

	for _, label := range c.Features.LabelSelectors {
		if len(labelSelector) == 0 {
			labelSelector = fmt.Sprintf("%s=%s", label.Name, label.Value)
			continue
		}
		labelSelector = fmt.Sprintf("%s,%s=%s", labelSelector, label.Name, label.Value)
	}
	return labelSelector
}

func (c *Config) GetPreConfiguredIdentities() []cosign.Identity {
	if len(c.PreConfiguredSaIdentities) == 0 {
		return []cosign.Identity{}
	}

	var identities []cosign.Identity
	for _, identity := range c.PreConfiguredSaIdentities {
		id := cosign.Identity{}
		if len(identity.Issuer) == 0 {
			id.IssuerRegExp = identity.IssuerRegExp
		} else {
			id.Issuer = identity.Issuer
		}

		if len(identity.Subject) == 0 {
			id.SubjectRegExp = identity.SubjectRegExp
		} else {
			id.Subject = identity.Subject
		}

		identities = append(identities, id)
	}
	return identities
}
