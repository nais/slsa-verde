package pod

import (
	v1 "k8s.io/api/core/v1"
)

type Info struct {
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

	var c []string
	for _, container := range pod.Spec.Containers {
		c = append(c, container.Image)
	}

	for _, container := range pod.Spec.InitContainers {
		c = append(c, container.Image)
	}

	return podInfo(pod, name, team, c), nil
}

func podInfo(pod *v1.Pod, name, team string, c []string) *Info {
	return &Info{
		ContainerImages: c,
		Name:            name,
		PodName:         pod.GetName(),
		Namespace:       pod.GetNamespace(),
		Team:            team,
	}
}
