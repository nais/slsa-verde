package pod

import (
	v1 "k8s.io/api/core/v1"
)

type Info struct {
	PredicateType   string
	ContainerImages []string
	Name            string
	Namespace       string
	PodName         string
	Team            string
}

func GetInfo(obj any) (*Info, error) {
	pod := obj.(*v1.Pod)
	labels := pod.GetLabels()
	name := labels["app.kubernetes.io/name"]
	team := labels["team"]
	predicateType := labels["nais.io/predicate-type"]

	var c []string
	for _, container := range pod.Spec.Containers {
		c = append(c, container.Image)
	}

	for _, container := range pod.Spec.InitContainers {
		c = append(c, container.Image)
	}

	return &Info{
		PredicateType:   predicateType,
		ContainerImages: c,
		Name:            name,
		PodName:         pod.GetName(),
		Namespace:       pod.GetNamespace(),
		Team:            team,
	}, nil
}
