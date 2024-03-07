package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/joho/godotenv"
	flag "github.com/spf13/pflag"

	"github.com/nais/dependencytrack/pkg/client"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/verify"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	_ "net/http/pprof"
	"picante/internal/attestation"
	"picante/internal/monitor"
)

type Cosign struct {
	IgnoreTLog bool   `json:"ignore-tlog"`
	KeyRef     string `json:"key-ref"`
	LocalImage bool   `json:"local-image"`
	RekorURL   string `json:"rekor-url"`
}

type GitHub struct {
	Organizations []string `json:"organizations"`
}

type DependencyTrack struct {
	Api      string `json:"api"`
	Username string `json:"username"`
	Password string `json:"password"`
	Team     string `json:"team"`
}

type Config struct {
	Cluster            string          `json:"cluster"`
	Cosign             Cosign          `json:"cosign"`
	DevelopmentMode    bool            `json:"development-mode"`
	GitHub             GitHub          `json:"github"`
	LogLevel           string          `json:"log-level"`
	MetricsBindAddress string          `json:"metrics-address"`
	DependencyTrack    DependencyTrack `json:"dependencytrack"`
}

var cfg = &Config{
	LogLevel: "debug",
}

func init() {
	viper.SetEnvPrefix("PICANTE")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))

	// Read configuration file from working directory and/or /etc.
	// File formats supported include JSON, TOML, YAML, HCL, envfile and Java properties config files
	viper.SetConfigName("picante")
	viper.AddConfigPath(".")
	viper.AddConfigPath("/etc/picante")

	flag.StringVar(&cfg.Cluster, "cluster", "", "Cluster name, e.g. dev")
	flag.BoolVar(&cfg.Cosign.IgnoreTLog, "cosign-ignore-tlog", false, "Ignore transparency log")
	flag.BoolVar(&cfg.Cosign.LocalImage, "cosign-local-image", false, "Use local image")
	flag.BoolVar(&cfg.DevelopmentMode, "development-mode", false, "Toggle for development mode")
	flag.StringVar(&cfg.Cosign.KeyRef, "cosign-key-ref", "", "The key reference, empty for keyless attestation")
	flag.StringVar(&cfg.Cosign.RekorURL, "cosign-rekor-url", "https://rekor.sigstore.dev", "Rekor URL")
	flag.StringVar(&cfg.LogLevel, "log-level", "info", "Log level")
	flag.StringVar(&cfg.MetricsBindAddress, "metrics-address", ":8080", "Bind address")
	flag.StringVar(&cfg.DependencyTrack.Api, "dependencytrack-api", "", "Salsa storage API endpoint")
	flag.StringVar(&cfg.DependencyTrack.Password, "dependencytrack-password", "", "Salsa storage password")
	flag.StringVar(&cfg.DependencyTrack.Team, "dependencytrack-team", "", "Salsa storage team")
	flag.StringVar(&cfg.DependencyTrack.Username, "dependencytrack-username", "", "Salsa storage username")
	flag.StringSliceVar(&cfg.GitHub.Organizations, "github-organizations", []string{}, "List of GitHub organizations to filter on")
}

func main() {
	err := setupConfig()
	if err != nil {
		log.WithError(err).Fatal("failed to setup config")
	}

	if err := setupLogger(); err != nil {
		log.WithError(err).Fatal("failed to setup logging")
	}

	mainLogger := log.WithFields(log.Fields{
		"component": "main",
	})

	mainLogger.Info("starting picante")
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	defer cancel()

	mainLogger.Info("setting up k8s client")
	kubeConfig := setupKubeConfig()
	k8sClient, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		mainLogger.WithError(err).Fatal("setting up k8s client")
	}

	mainLogger.Info("setting up informer")
	tweakListOpts := informers.WithTweakListOptions(
		func(options *v1.ListOptions) {
			options.FieldSelector = "metadata.namespace!=kube-system," +
				"metadata.namespace!=kube-public," +
				"metadata.namespace!=cnrm-system"
		})

	verifyCmd := &verify.VerifyAttestationCommand{
		RekorURL:   cfg.Cosign.RekorURL,
		LocalImage: cfg.Cosign.LocalImage,
		IgnoreTlog: cfg.Cosign.IgnoreTLog,
	}

	opts, err := attestation.NewVerifyAttestationOpts(
		verifyCmd,
		cfg.GitHub.Organizations,
		cfg.Cosign.KeyRef,
	)
	if err != nil {
		mainLogger.WithError(err).Fatal("failed to setup verify attestation opts")
	}

	mainLogger.Info("setting up dtrack client")
	s := client.New(cfg.DependencyTrack.Api, cfg.DependencyTrack.Username, cfg.DependencyTrack.Password, client.WithApiKeySource(cfg.DependencyTrack.Team))
	if err != nil {
		mainLogger.WithError(err).Fatal("failed to get teams")
	}

	factory := informers.NewSharedInformerFactoryWithOptions(k8sClient, 0, tweakListOpts)
	if err = setupInformers(
		ctx,
		mainLogger,
		monitor.NewMonitor(ctx, s, opts, cfg.Cluster),
		factory.Apps().V1().ReplicaSets().Informer(),
		// TODO Exclude jobs as they are not needed for now
		// factory.Batch().V1().Jobs().Informer(),
		factory.Apps().V1().StatefulSets().Informer(),
		factory.Apps().V1().DaemonSets().Informer(),
	); err != nil {
		mainLogger.WithError(err).Fatal("failed to setup informers")
	}

	// Server for pprof
	go func() {
		fmt.Println(http.ListenAndServe("localhost:6060", nil))
	}()

	defer runtime.HandleCrash()

	<-ctx.Done()
	mainLogger.Info("shutting down")
}

func setupKubeConfig() *rest.Config {
	var kubeConfig *rest.Config
	var err error

	if envConfig := os.Getenv("KUBECONFIG"); envConfig != "" {
		kubeConfig, err = clientcmd.BuildConfigFromFlags("", envConfig)
		if err != nil {
			panic(err.Error())
		}
		log.Infof("starting with kubeconfig: %s", envConfig)
	} else {
		kubeConfig, err = rest.InClusterConfig()
		if err != nil {
			log.WithError(err).Fatal("failed to get kubeconfig")
		}
		log.Infof("starting with in-cluster config: %s", kubeConfig.Host)
	}
	return kubeConfig
}

func setupInformers(ctx context.Context, log *log.Entry, monitor *monitor.Config, informers ...cache.SharedIndexInformer) error {
	for _, informer := range informers {
		log.Infof("setting up informer")
		err := informer.SetWatchErrorHandler(cache.DefaultWatchErrorHandler)
		if err != nil {
			return fmt.Errorf("set watch error handler: %w", err)
		}

		log.Info("setting up monitor, event handler")
		event, err := informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
			AddFunc:    monitor.OnAdd,
			UpdateFunc: monitor.OnUpdate,
			DeleteFunc: monitor.OnDelete,
		})
		if err != nil {
			return fmt.Errorf("add event handler: %w", err)
		}

		go informer.Run(ctx.Done())
		if !cache.WaitForCacheSync(ctx.Done(), informer.HasSynced) {
			runtime.HandleError(fmt.Errorf("timed out waiting for caches to sync"))
			return fmt.Errorf("timed out waiting for caches to sync")
		}

		log.Infof("informer cache synced: %v", event.HasSynced())
	}
	return nil
}

func setupConfig() error {
	log.Info("-------- setting up configuration -----------")
	err := Load()
	if err != nil {
		return fmt.Errorf("loading configuration: %w", err)
	}
	log.Info("-------- configuration loaded ----------")
	return nil
}

func setupLogger() error {
	if cfg.DevelopmentMode {
		log.SetLevel(log.DebugLevel)
		formatter := &log.TextFormatter{
			ForceColors:            true,
			TimestampFormat:        "02-01-2006 15:04:05",
			FullTimestamp:          true,
			DisableLevelTruncation: true,
		}
		log.SetFormatter(formatter)
		return nil
	}

	formatter := log.JSONFormatter{
		TimestampFormat: time.RFC3339,
	}

	log.SetFormatter(&formatter)
	log.SetLevel(logLevel())
	return nil
}

func logLevel() log.Level {
	l, err := log.ParseLevel(viper.GetString(cfg.LogLevel))
	if err != nil {
		l = log.InfoLevel
	}
	return l
}

func Load() error {
	var err error
	err = godotenv.Load()
	if err != nil {
		return fmt.Errorf("loading .env file: %w", err)
	}

	requiredFlags := map[string]bool{
		"cluster":                  false,
		"dependencytrack-api":      false,
		"dependencytrack-username": false,
		"dependencytrack-password": false,
		"dependencytrack-team":     false,
		"github-organizations":     false,
	}

	redacted := []string{
		"dependencytrack-username",
		"dependencytrack-password",
		"cosign-key-ref",
	}

	flag.VisitAll(func(f *flag.Flag) {
		name := strings.ToUpper(strings.Replace(f.Name, "-", "_", -1))
		if value, ok := os.LookupEnv(name); ok {
			err = flag.Set(f.Name, value)
			if err != nil {
				log.Fatalf("setting flag %v", f.Name)
			}

			// all flags in requiredFlags must be set, mark them as seen
			if _, ok := requiredFlags[f.Name]; ok {
				requiredFlags[f.Name] = true
			}

			// if the flag is redacted, log it as such
			if contains(redacted, f.Name) {
				log.Infof("setting flag %v: ***REDACTED***", f.Name)
			} else {
				log.Infof("setting flag %v: %v", f.Name, value)
			}
		}
	})

	// check if all required flags are set
	for k, v := range requiredFlags {
		if !v {
			log.Fatalf("required flag %v is not set", k)
		}
	}

	flag.Parse()
	return nil
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
