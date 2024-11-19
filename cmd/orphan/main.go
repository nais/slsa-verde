package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
	"github.com/nais/dependencytrack/pkg/client"
	log "github.com/sirupsen/logrus"

	"sigs.k8s.io/controller-runtime/pkg/manager"
	"slsa-verde/internal/orphan"
	"slsa-verde/internal/orphan/config"
)

func main() {
	var err error
	err = godotenv.Load()
	if err != nil {
		fmt.Println("No .env file found")
	}
	dprackUrl := os.Getenv("DEPENDENCYTRACK_API")
	dprackUser := os.Getenv("DEPENDENCYTRACK_USERNAME")
	dprackPass := os.Getenv("DEPENDENCYTRACK_PASSWORD")
	dprackTeam := os.Getenv("DEPENDENCYTRACK_TEAM")
	cluster := os.Getenv("CLUSTER")
	logLevel := os.Getenv("LOG_LEVEL")
	dryRun, err := strconv.ParseBool(os.Getenv("DRY_RUN"))
	if err != nil {
		log.Errorf("Error parsing DRY_RUN: %v", err)
		return
	}

	err = setupLogger(logLevel)
	if err != nil {
		log.Errorf("Error setting up logger: %v", err)
		return
	}

	log.Infoln("DRY_RUN:", dryRun)
	kconfig, err := config.ClusterConfig(log.WithField("system", "cluster-config"))
	if err != nil {
		log.Errorf("Error getting cluster config: %v", err)
		return
	}

	rScheme, err := config.RegisterScheme(log.WithField("system", "register-scheme"))
	if err != nil {
		log.Errorf("Error registering rScheme: %v", err)
		return
	}

	mgr, err := manager.New(kconfig, manager.Options{Scheme: rScheme})
	if err != nil {
		log.Errorf("Error creating manager: %v", err)
		return
	}

	go func() {
		if err := mgr.Start(context.Background()); err != nil {
			log.Errorf("Error starting manager: %v", err)
			os.Exit(1)
		}
	}()

	cache := mgr.GetCache()
	if !cache.WaitForCacheSync(context.Background()) {
		log.Error("Cache sync failed")
		return
	}
	log.Infoln("Cache synced successfully")

	ctrlClient := mgr.GetClient()

	dpClient := client.New(
		dprackUrl,
		dprackUser,
		dprackPass,
		client.WithApiKeySource(dprackTeam),
		client.WithRetry(4, 3*time.Second),
	)

	ctx := context.Background()
	o := orphan.New(ctx, dpClient, ctrlClient, cluster, log.WithField("system", "orphan-projects"))
	if err = o.Run(dryRun); err != nil {
		log.Errorf("Error running orphan projects: %v", err)
		return
	}
}

func setupLogger(loglevel string) error {
	formatter := log.JSONFormatter{
		TimestampFormat: time.RFC3339,
	}

	log.SetFormatter(&formatter)
	log.SetLevel(set(loglevel))
	return nil
}

func set(loglevel string) log.Level {
	l, err := log.ParseLevel(loglevel)
	if err != nil {
		l = log.InfoLevel
	}
	return l
}
