package pod

import (
	v1 "k8s.io/api/core/v1"
)

const (
	DefaultPredicateType          = "cyclonedx"
	AppK8sIoNameLabelKey          = "app.kubernetes.io/name"
	SalsaKeyRefLabelKey           = "nais.io/salsa-key-ref"
	SalsaKeylessProviderLabelKey  = "nais.io/salsa-keyRef-provider"
	SalsaPredicateLabelKey        = "nais.io/salsa-predicateType"
	TeamLabelKey                  = "team"
	AppLabelKey                   = "app"
	IgnoreTransparencyLogLabelKey = "nais.io/salsa-ignore-transparency-log"
)

type Info struct {
	ContainerImages []Container
	Name            string
	Namespace       string
	PodName         string
	Team            string
	Verifier        *Verifier
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

func GetInfo(obj any) *Info {
	if obj == nil {
		return nil
	}

	pod := obj.(*v1.Pod)
	labels := pod.GetLabels()

	var c []Container
	for _, container := range pod.Spec.Containers {
		c = append(c, Container{
			Image: container.Image,
			Name:  container.Name,
		})
	}

	for _, container := range pod.Spec.InitContainers {
		c = append(c, Container{
			Image: container.Image,
			Name:  container.Name,
		})
	}

	return &Info{
		ContainerImages: c,
		Name:            getAppName(labels),
		Namespace:       pod.GetNamespace(),
		PodName:         pod.GetName(),
		Team:            labels[TeamLabelKey],
		Verifier: &Verifier{
			PredicateType:   labels[SalsaPredicateLabelKey],
			KeyRef:          labels[SalsaKeyRefLabelKey],
			KeylessProvider: labels[SalsaKeylessProviderLabelKey],
			IgnoreTLog:      labels[IgnoreTransparencyLogLabelKey],
		},
	}
}

func getAppName(labels map[string]string) string {
	appName := labels[AppK8sIoNameLabelKey]
	if appName == "" {
		appName = labels[AppLabelKey]
	}
	return appName
}

func (p *Info) IgnoreTLog() bool {
	if p.Verifier == nil {
		return false
	}

	if p.Verifier.IgnoreTLog == "true" {
		return true
	}
	return false
}

func (p *Info) GetPredicateType() string {
	if p.Verifier == nil {
		return DefaultPredicateType
	}
	if p.Verifier.PredicateType == "" {
		return DefaultPredicateType
	}
	return p.Verifier.PredicateType
}

func (p *Info) KeylessVerification() bool {
	if p.Verifier == nil {
		return false
	}

	if p.Verifier.KeyRef == "true" {
		return false
	}
	return true
}

func (p *Info) ProjectName(cluster string) string {
	return cluster + ":" + p.Name + ":" + p.Namespace
}
