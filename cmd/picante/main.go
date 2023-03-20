package main

import (
	// Load all client-go auth plugins

	"context"
	"flag"
	"fmt"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/verify"
	"os"
	"os/signal"
	"picante/internal/attestation"
	"picante/internal/config"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"picante/internal/monitor"
	"picante/internal/storage"
)

var cfg = config.DefaultConfig()

const (
	KUBECONFIG = "KUBECONFIG"
)

func init() {
	flag.StringVar(&cfg.MetricsBindAddress, "metrics-bind-address", ":8080", "Bind address")
	flag.StringVar(&cfg.LogLevel, "log-level", "debug", "Which log level to output")
	flag.StringVar(&cfg.Storage.SbomApi, "sbom-api", "http://localhost:8888/api/v1/bom", "SBOM API endpoint")
	flag.StringVar(&cfg.Storage.SbomApiKey, "sbom-api-key", "BjaW3EoqJbKKGBzc1lcOkBijjsC5rL2O", "SBOM API key")
	flag.StringVar(&cfg.ProjectID, "project-id", "", "Project ID")
	flag.StringVar(&cfg.Issuer, "issuer", "https://picante.ttl.sh", "Issuer")
	flag.StringVar(&cfg.KeyRef, "key-ref", "hack/cosign.pub", "Key reference")
	flag.BoolVar(&cfg.LocalImage, "local-image", false, "Local image")
	flag.BoolVar(&cfg.IgnoreTLog, "ignore-tlog", false, "Ignore TLog")
	flag.StringVar(&cfg.RekorURL, "rekor-url", "https://rekor.sigstore.dev", "Rekor URL")
}

func main() {
	flag.Parse()
	setupLogger()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	defer cancel()

	var kubeConfig = setupKubeConfig()
	k8sClient, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		log.WithError(err).Fatal("setting up k8s client")
	}

	factory := informers.NewSharedInformerFactory(k8sClient, 0)
	podInformer := factory.Core().V1().Pods()
	informer := podInformer.Informer()
	err = informer.SetWatchErrorHandler(errorHandler)
	if err != nil {
		log.Errorf("error setting watch error handler: %v", err)
		return
	}

	defer runtime.HandleCrash()

	s := storage.NewClient(cfg.Storage.SbomApi, cfg.Storage.SbomApiKey)
	if err != nil {
		log.WithError(err).Fatal("failed to get teams")
	}

	verifyCmd := &verify.VerifyAttestationCommand{
		CheckClaims: false,
		KeyRef:      cfg.KeyRef,
		RekorURL:    cfg.RekorURL,
		LocalImage:  cfg.LocalImage,
		IgnoreTlog:  cfg.IgnoreTLog,
	}

	opts := &attestation.VerifyAttestationOpts{
		VerifyCmd: verifyCmd,
		ProjectID: cfg.ProjectID,
		Issuer:    cfg.Issuer,
	}

	m := monitor.NewMonitor(s, opts)

	_, err = informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    m.OnAdd,
		UpdateFunc: m.OnUpdate,
		DeleteFunc: m.OnDelete,
	})
	if err != nil {
		log.Errorf("error setting event handler: %v", err)
		return
	}

	go informer.Run(ctx.Done())
	waitForCacheSync(ctx.Done(), informer.HasSynced)

	<-ctx.Done()
	log.Info("shutting down")
}

func setupKubeConfig() *rest.Config {
	var kubeConfig *rest.Config
	var err error

	if envConfig := os.Getenv(KUBECONFIG); envConfig != "" {
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

func errorHandler(r *cache.Reflector, err error) {
	fmt.Println("watch error ", err)
}

func setupLogger() {
	log.SetFormatter(&log.JSONFormatter{})
	l, err := log.ParseLevel(cfg.LogLevel)
	if err != nil {
		log.Fatal(err)
	}
	log.SetLevel(l)
}

func waitForCacheSync(stop <-chan struct{}, cacheSyncs ...cache.InformerSynced) bool {
	max := time.Millisecond * 100
	delay := time.Millisecond
	f := func() bool {
		for _, syncFunc := range cacheSyncs {
			if !syncFunc() {
				return false
			}
		}
		return true
	}
	for {
		select {
		case <-stop:
			return false
		default:
		}
		res := f()
		if res {
			return true
		}
		delay *= 2
		if delay > max {
			delay = max
		}

		select {
		case <-stop:
			return false
		case <-time.After(delay):
		}
	}
}
