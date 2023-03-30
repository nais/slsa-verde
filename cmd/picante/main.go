package main

import (
	"context"
	"fmt"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/verify"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	factory := informers.NewSharedInformerFactoryWithOptions(k8sClient, 0, informers.WithTweakListOptions(
		func(options *v1.ListOptions) {
			if cfg.Features.Enabled && len(cfg.Features.LabelSelectors) > 0 {
				options.LabelSelector = cfg.GetLabelSelectors()
			}
			options.FieldSelector = "status.phase=Running"
		}),
	)
	podInformer := factory.Core().V1().Pods().Informer()
	err = podInformer.SetWatchErrorHandler(cache.DefaultWatchErrorHandler)
	if err != nil {
		log.Errorf("error setting watch error handler: %v", err)
		return
	}

	defer runtime.HandleCrash()

	opts := &attestation.VerifyAttestationOpts{
		VerifyCmd: &verify.VerifyAttestationCommand{
			RekorURL:   cfg.Cosign.RekorURL,
			LocalImage: cfg.Cosign.LocalImage,
			IgnoreTlog: cfg.Cosign.IgnoreTLog,
		},
		KeyRef:     cfg.Cosign.KeyRef,
		Identities: cfg.GetIdentities(),
		Logger:     log.WithFields(log.Fields{"component": "attestation"}),
	}

	log.Info("setting up storage client")
	s := storage.NewClient(cfg.Storage.Api, cfg.Storage.ApiKey)
	if err != nil {
		log.WithError(err).Fatal("failed to get teams")
	}

	m := monitor.NewMonitor(ctx, s, opts)

	log.Info("setting up informer event handler")
	_, err = podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    m.OnAdd,
		UpdateFunc: m.OnUpdate,
		DeleteFunc: m.OnDelete,
	})

	if err != nil {
		log.Errorf("error setting event handler: %v", err)
		return
	}

	go podInformer.Run(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), podInformer.HasSynced) {
		runtime.HandleError(fmt.Errorf("timed out waiting for caches to sync"))
		return
	}

	log.Infof("informer cache synced")

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
		config.StorageApi,
		config.StorageApiKey,
		config.CosignLocalImage,
		config.Identities,
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
	l, err := log.ParseLevel(viper.GetString(config.LogLevel))
	if err != nil {
		l = log.InfoLevel
	}
	return l
}
