package pod

import (
	v1 "k8s.io/api/core/v1"
)

const (
	DefaultPredicateType = "cyclonedx"
)

type Info struct {
	ContainerImages []string
	Name            string
	Namespace       string
	Verifier        *Verifier
	PodName         string
	Team            string
}

type Verifier struct {
	KeyRef          string
	KeylessProvider string
	PredicateType   string
}

func GetInfo(obj any) (*Info, error) {
	pod := obj.(*v1.Pod)
	labels := pod.GetLabels()
	name := labels[LabelTypeAppK8sIoName.String()]
	team := labels[LabelTypeTeamLabel.String()]
	predicateType := labels[LabelTypeSalsaPredicateLabel.String()]
	keyRef := labels[LabelTypeSalsaKeyRefLabel.String()]
	KeylessProvider := labels[LabelTypeSalsaKeylessProvider.String()]

	var c []string
	for _, container := range pod.Spec.Containers {
		c = append(c, container.Image)
	}

	for _, container := range pod.Spec.InitContainers {
		c = append(c, container.Image)
	}

	return &Info{
		ContainerImages: c,
		Name:            name,
		Namespace:       pod.GetNamespace(),
		PodName:         pod.GetName(),
		Team:            team,
		Verifier: &Verifier{
			PredicateType:   predicateType,
			KeyRef:          keyRef,
			KeylessProvider: KeylessProvider,
		},
	}, nil
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
