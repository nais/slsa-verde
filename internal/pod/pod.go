package pod

import (
	v1 "k8s.io/api/core/v1"
)

const (
	DefaultAppK8sIoName   = "app.kubernetes.io/name"
	DefaultKeyRefLabel    = "nais.io/salsa-key-ref"
	DefaultPredicateLabel = "nais.io/salsa-predicate"
	DefaultPredicateType  = "cyclonedx"
	DefaultTeamLabel      = "team"
)

type Info struct {
	ContainerImages []string
	KeyRef          string
	Name            string
	Namespace       string
	PodName         string
	PredicateType   string
	Team            string
}

func GetInfo(obj any) (*Info, error) {
	pod := obj.(*v1.Pod)
	labels := pod.GetLabels()
	name := labels[DefaultAppK8sIoName]
	team := labels[DefaultTeamLabel]
	predicateType := labels[DefaultPredicateLabel]
	keyRef := labels[DefaultKeyRefLabel]

	var c []string
	for _, container := range pod.Spec.Containers {
		c = append(c, container.Image)
	}

	for _, container := range pod.Spec.InitContainers {
		c = append(c, container.Image)
	}

	return &Info{
		ContainerImages: c,
		KeyRef:          keyRef,
		Name:            name,
		Namespace:       pod.GetNamespace(),
		PodName:         pod.GetName(),
		PredicateType:   predicateType,
		Team:            team,
	}, nil
}

func (p *Info) GetPredicateType() string {
	if p.PredicateType == "" {
		return DefaultPredicateType
	}
	return p.PredicateType
}

func (p *Info) KeylessVerification() bool {
	if p.KeyRef == "true" {
		return false
	}
	return true
}
