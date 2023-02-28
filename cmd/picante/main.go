package main

import (
	// Load all client-go auth plugins

	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
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
	"picante/internal/attestation"
	"picante/internal/config"
	"picante/internal/picante"
)

var cfg = config.DefaultConfig()

func init() {
	flag.StringVar(&cfg.MetricsBindAddress, "metrics-bind-address", ":8080", "Bind address")
	flag.StringVar(&cfg.LogLevel, "log-level", "debug", "Which log level to output")
	flag.StringVar(&cfg.SbomApi, "sbom-api", "", "SBOM API endpoint")
}

func main() {

	verify, err := attestation.Verify(context.Background(), []string{"ttl.sh/picante:1h"}, "/Users/tommytroen/ws/nav/picante/internal/attestation/testdata/cosign.pub")
	if err != nil {
		log.Fatalf("failed to verify image attestations: %v", err)
	}
	fmt.Printf("verify: %v\n", verify)
}

func main2() {
	flag.Parse()
	setupLogger()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	defer cancel()

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
	p := picante.New(cfg.SbomApi)

	_, err = informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    p.OnAdd,
		UpdateFunc: p.OnUpdate,
		DeleteFunc: p.OnDelete,
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
