package main

import (
	"context"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/verify"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"os"
	"os/signal"
	"picante/internal/attestation"
	"picante/internal/config"
	"syscall"
	"time"

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

const (
	KUBECONFIG = "KUBECONFIG"
)

func main() {
	cfg, err := setupConfig()
	if err != nil {
		log.WithError(err).Fatal("failed to setup config")
	}

	if err := setupLogger(); err != nil {
		log.WithError(err).Fatal("failed to setup logging")
	}

	log.Info("starting picante")
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	defer cancel()

	log.Info("setting up k8s client")
	var kubeConfig = setupKubeConfig()
	k8sClient, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		log.WithError(err).Fatal("setting up k8s client")
	}

	log.Info("setting up informer")
	factory := informers.NewSharedInformerFactory(k8sClient, 0)
	podInformer := factory.Core().V1().Pods()
	informer := podInformer.Informer()
	err = informer.SetWatchErrorHandler(cache.DefaultWatchErrorHandler)
	if err != nil {
		log.Errorf("error setting watch error handler: %v", err)
		return
	}

	defer runtime.HandleCrash()

	log.Info("setting up storage client")
	s := storage.NewClient(cfg.Storage.Api, cfg.Storage.ApiKey)
	if err != nil {
		log.WithError(err).Fatal("failed to get teams")
	}

	verifyCmd := &verify.VerifyAttestationCommand{
		KeyRef:     cfg.Cosign.KeyRef,
		RekorURL:   cfg.Cosign.RekorURL,
		LocalImage: cfg.Cosign.LocalImage,
		IgnoreTlog: cfg.Cosign.IgnoreTLog,
	}

	opts := &attestation.VerifyAttestationOpts{
		VerifyCmd: verifyCmd,
		ProjectID: cfg.Identity.ProjectID,
		Issuer:    cfg.Identity.Issuer,
		Logger:    log.WithFields(log.Fields{"component": "attestation"}),
	}

	m := monitor.NewMonitor(ctx, s, opts)

	log.Info("setting up event handler")
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

func setupConfig() (*config.Config, error) {
	log.Info("-------- setting up configuration ---------")
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}

	if err := config.Validate([]string{
		config.MetricsAddress,
		config.LogLevel,
		config.StorageApi,
		config.StorageApiKey,
		config.CosignLocalImage,
		config.CosignIgnoreTLog,
		config.IdentityProjectID,
		config.IdentityIssuer,
	}); err != nil {
		return cfg, err
	}

	config.Print([]string{
		config.StorageApiKey,
	})

	log.Info("-------- configuration loaded --------")
	return cfg, nil
}

func setupLogger() error {
	if viper.GetBool(config.DevelopmentMode) {
		log.SetLevel(log.DebugLevel)
		formatter := &log.TextFormatter{
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
	l, err := log.ParseLevel(viper.GetString(config.LogLevel))
	if err != nil {
		return err
	}
	log.SetLevel(l)
	return nil
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
