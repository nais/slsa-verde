package config

import (
	"fmt"
	"os"

	nais_io_v1 "github.com/nais/liberator/pkg/apis/nais.io/v1"
	log "github.com/sirupsen/logrus"
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func ClusterConfig(log *log.Entry) (*rest.Config, error) {
	var kconfig *rest.Config
	var err error
	if _, inCluster := os.LookupEnv("KUBERNETES_SERVICE_HOST"); inCluster {
		log.Info("Using in-cluster kubeconfig")
		kconfig, err = rest.InClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("error creating in-cluster config: %v", err)
		}
	} else {
		log.Info("Using local kubeconfig")
		kconfig, err = clientcmd.BuildConfigFromFlags("", clientcmd.RecommendedHomeFile)
		if err != nil {
			return nil, fmt.Errorf("error creating local kubeconfig: %v", err)
		}
	}
	return kconfig, nil
}

func RegisterScheme(log *log.Entry) (*runtime.Scheme, error) {
	s := scheme.Scheme
	err := appsv1.AddToScheme(s)
	if err != nil {
		return nil, fmt.Errorf("error registering apps/v1 schema: %v", err)
	}

	log.Infoln("Deployment schema registered successfully")
	err = nais_io_v1.AddToScheme(s)
	if err != nil {
		return nil, fmt.Errorf("error registering nais.io/v1 schema: %v", err)
	}
	log.Infoln("Job schema registered successfully")
	return s, nil
}
