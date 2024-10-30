package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/joho/godotenv"
	flag "github.com/spf13/pflag"

	_ "net/http/pprof"
	"slsa-verde/internal/attestation"
	"slsa-verde/internal/monitor"

	"github.com/nais/dependencytrack/pkg/client"
	nais_io_v1 "github.com/nais/liberator/pkg/apis/nais.io/v1"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/verify"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
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
	Cluster             string          `json:"cluster"`
	Cosign              Cosign          `json:"cosign"`
	DevelopmentMode     bool            `json:"development-mode"`
	GitHub              GitHub          `json:"github"`
	LogLevel            string          `json:"log-level"`
	MetricsBindAddress  string          `json:"metrics-address"`
	DependencyTrack     DependencyTrack `json:"dependencytrack"`
	Namespace           string          `json:"namespace"`
	InformerReListHours int             `json:"informer-re-list-hours"`
}

type SlsaInformers map[string]cache.SharedIndexInformer

var cfg = &Config{
	LogLevel: "debug",
}

func init() {
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
	flag.StringVar(&cfg.Namespace, "namespace", "", "Specify a single namespace to watch")
	flag.IntVar(&cfg.InformerReListHours, "informer-re-list-hours", 6, "Interval for re-listing of resources in hours")
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

	mainLogger.Info("starting slsa-verde")

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	ctx, signalStop := signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT)
	defer signalStop()

	mainLogger.Info("setting up k8s client")
	kubeConfig := setupKubeConfig()
	k8sClient, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		mainLogger.WithError(err).Fatal("setting up k8s client")
	}

	dynamicClient, err := dynamic.NewForConfig(kubeConfig)
	if err != nil {
		mainLogger.WithError(err).Fatal("create dynamic client: %w", err)
	}

	if err := run(ctx, k8sClient, dynamicClient, mainLogger); err != nil {
		mainLogger.WithError(err).Fatal("error in run()")
	}
}

func run(ctx context.Context, k8sClient *kubernetes.Clientset, dynamicClient *dynamic.DynamicClient, mainLogger *log.Entry) error {
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
		return fmt.Errorf("failed to create attestation options: %w", err)
	}

	mainLogger.Info("setting up dtrack client")
	s := client.New(
		cfg.DependencyTrack.Api,
		cfg.DependencyTrack.Username,
		cfg.DependencyTrack.Password,
		client.WithApiKeySource(cfg.DependencyTrack.Team),
		client.WithRetry(2, 2*time.Second),
	)
	if err != nil {
		return fmt.Errorf("failed to create dtrack client: %w", err)
	}

	server := &http.Server{
		Addr: ":8000",
	}

	http.Handle("/metrics", promhttp.Handler())
	go func() {
		if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			mainLogger.WithError(err).Fatal("failed to start metrics server")
		}
		mainLogger.Info("Stopped serving new connections.")
	}()

	m := monitor.NewMonitor(ctx, s, opts, cfg.Cluster)
	if err = startInformers(ctx, m, k8sClient, dynamicClient, cfg.Namespace, mainLogger); err != nil {
		return fmt.Errorf("start informers: %w", err)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	shutdownCtx, shutdownRelease := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownRelease()

	if err := server.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown server: %w", err)
	}
	mainLogger.Info("Graceful shutdown complete.")
	return nil
}

func prepareInformers(ctx context.Context, k8sClient *kubernetes.Clientset, dynamicClient *dynamic.DynamicClient, namespace string, logger *log.Entry) SlsaInformers {
	logger.Info("prepare informer(s)")
	// default ignore system namespaces
	switch namespace {
	case "":
		namespace = "metadata.namespace!=kube-system," +
			"metadata.namespace!=kube-public," +
			"metadata.namespace!=cnrm-system," +
			"metadata.namespace!=kyverno," +
			"metadata.namespace!=linkerd"
	default:
		namespace = "metadata.namespace=" + namespace
	}

	tweakListOpts := informers.WithTweakListOptions(
		func(options *v1.ListOptions) {
			options.FieldSelector = namespace
		})
	dynTweakListOpts := dynamicinformer.TweakListOptionsFunc(
		func(options *v1.ListOptions) {
			options.FieldSelector = namespace
		})
	factory := informers.NewSharedInformerFactoryWithOptions(k8sClient, 1*time.Hour, tweakListOpts)
	dinf := dynamicinformer.NewFilteredDynamicSharedInformerFactory(dynamicClient, 1*time.Hour, "", dynTweakListOpts)

	infs := SlsaInformers{
		"deployment": factory.Apps().V1().Deployments().Informer(),
	}

	_, err := dynamicClient.Resource(nais_io_v1.GroupVersion.WithResource("naisjobs")).List(ctx, v1.ListOptions{})
	if err != nil {
		logger.Warn("could not list naisjobs, skipping informer setup for naisjobs, " + err.Error())
	} else {
		infs["naisjobs"] = dinf.ForResource(nais_io_v1.GroupVersion.WithResource("naisjobs")).Informer()
	}

	return infs
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

func startInformers(ctx context.Context, monitor *monitor.Config, k8sClient *kubernetes.Clientset, dynamicClient *dynamic.DynamicClient, namespace string, log *log.Entry) error {
	log.Infof("setting up informer(s) with %d-hours interval for re-listing of resources", cfg.InformerReListHours)

	ticker := time.NewTicker(time.Duration(cfg.InformerReListHours) * time.Hour)
	defer ticker.Stop()

	for {
		// Create a new context for each informer restart
		informerCtx, cancel := context.WithCancel(ctx)

		// Recreate the informer factory and set up the informers
		slsaInformers := prepareInformers(informerCtx, k8sClient, dynamicClient, namespace, log)
		for name, informer := range slsaInformers {
			l := log.WithField("resource", name)
			err := informer.SetWatchErrorHandler(cache.DefaultWatchErrorHandler)
			if err != nil {
				cancel()
				return fmt.Errorf("set watch error handler: %w", err)
			}

			l.Info("setting up monitor for resource")
			_, err = informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
				AddFunc:    monitor.OnAdd,
				UpdateFunc: monitor.OnUpdate,
				DeleteFunc: monitor.OnDelete,
			})
			if err != nil {
				cancel()
				return fmt.Errorf("add event handler: %w", err)
			}

			go informer.Run(informerCtx.Done())
			if !cache.WaitForCacheSync(informerCtx.Done(), informer.HasSynced) {
				runtime.HandleError(fmt.Errorf("timed out waiting for caches to sync"))
				cancel()
				return fmt.Errorf("timed out waiting for caches to sync")
			}

			l.Infof("informer cache synced: %v", informer.HasSynced())
		}

		// Wait for ticker or context cancellation
		select {
		case <-ticker.C:
			log.Infof("Restarting informers after %d-hour interval", cfg.InformerReListHours)
			cancel() // Stop the current informers
		case <-ctx.Done():
			cancel()
			return nil
		}
	}
}

func setupConfig() error {
	log.Info("-------- setting up configuration -----------")
	err := Load()
	if err != nil {
		return fmt.Errorf("loading configuration: %w", err)
	}
	log.Info("-------- configuration loaded ---------------")
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
	l, err := log.ParseLevel(cfg.LogLevel)
	if err != nil {
		l = log.InfoLevel
	}
	return l
}

func Load() error {
	var err error
	err = godotenv.Load()
	if err != nil {
		log.Debug("not loading from .env file")
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
