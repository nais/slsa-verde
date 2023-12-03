package workload

import (
	"github.com/sirupsen/logrus"
	appv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/batch/v1"
)

const (
	DefaultPredicateType          = "cyclonedx"
	AppK8sIoNameLabelKey          = "app.kubernetes.io/name"
	AppK8sIoInstanceLabelKey      = "app.kubernetes.io/instance"
	SalsaKeyRefLabelKey           = "nais.io/salsa-key-ref"
	SalsaKeylessProviderLabelKey  = "nais.io/salsa-keyRef-provider"
	SalsaPredicateLabelKey        = "nais.io/salsa-predicateType"
	TeamLabelKey                  = "team"
	AppLabelKey                   = "app"
	IgnoreTransparencyLogLabelKey = "nais.io/salsa-ignore-transparency-log"
)

type Workload interface {
	GetName() string
	GetNamespace() string
	GetTeam() string
	Active() bool
	GetLabels() map[string]string
	GetKind() string
	GetContainers() []Container
	GetVerifier() *Verifier
	GetIdentifier() string
}

type metadata struct {
	Name      string
	Namespace string
	Team      string
	Kind      string
	Labels    map[string]string
}

type Container struct {
	Image string
	Name  string
}

type Verifier struct {
	KeyRef          string
	KeylessProvider string
	PredicateType   string
	IgnoreTLog      string
}

func GetMetadata(obj any, log *logrus.Entry) Workload {
	if obj == nil {
		return nil
	}

	if log == nil {
		log = logrus.WithFields(logrus.Fields{"package": "workload"})
	}

	var w Workload
	switch v := obj.(type) {
	case *appv1.StatefulSet:
		w = NewStatefulSet(v, log)
	case *v1.Job:
		w = NewJob(v, log)
	case *appv1.ReplicaSet:
		w = NewReplicaSet(v, log)
	default:
		log.Debugf("unknown workload type: %T", v)
	}
	return w
}

func ProjectName(w Workload, cluster, containerName string) string {
	projectName := cluster + ":" + w.GetNamespace() + ":" + w.GetName()
	if w.GetName() == containerName {
		return projectName
	}
	return projectName + ":" + containerName
}

func setName(labels map[string]string) string {
	appName := labels[AppK8sIoNameLabelKey]
	if appName == "" {
		appName = labels[AppLabelKey]
	}
	if appName == "" {
		appName = labels[AppK8sIoInstanceLabelKey]
	}
	return appName
}

func IgnoreTLog(w Workload) bool {
	verifier := w.GetVerifier()
	if verifier == nil {
		return false
	}

	if verifier.IgnoreTLog == "true" {
		return true
	}
	return false
}

func GetPredicateType(w Workload) string {
	verifier := w.GetVerifier()
	if verifier == nil {
		return DefaultPredicateType
	}
	if verifier.PredicateType == "" {
		return DefaultPredicateType
	}
	return verifier.PredicateType
}

func KeylessVerification(w Workload) bool {
	verifier := w.GetVerifier()
	if verifier == nil {
		return false
	}

	if verifier.KeyRef == "true" {
		return false
	}
	return true
}

func setVerifier(labels map[string]string) *Verifier {
	return &Verifier{
		PredicateType:   labels[SalsaPredicateLabelKey],
		KeyRef:          labels[SalsaKeyRefLabelKey],
		KeylessProvider: labels[SalsaKeylessProviderLabelKey],
		IgnoreTLog:      labels[IgnoreTransparencyLogLabelKey],
	}
}
