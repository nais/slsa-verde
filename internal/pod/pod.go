package pod

import (
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
)

type Info struct {
	ContainerImages []string
	Name            string
	Team            string
	Verify          bool
}

type Image struct {
	Ref string
}

func GetInfo(obj any) *Info {
	pod := obj.(*v1.Pod)
	name := pod.Labels["app.kubernetes.io/name"]
	team := pod.Labels["team"]
	if name == "" || team == "" {
		log.Debugf("no app.kubernetes.io/name or team label: %s", pod.Name)
		return nil
	}

	var c []string

	for _, container := range pod.Spec.Containers {
		log.Debugf("conainer image %s", container.Image)
		c = append(c, container.Image)
	}

	for _, container := range pod.Spec.InitContainers {
		log.Debugf("init container image %s", container.Image)
		c = append(c, container.Image)
	}

	return podInfo(pod, name, team, c)
}

func podInfo(pod *v1.Pod, name, team string, c []string) *Info {
	return &Info{
		Name:            name,
		ContainerImages: c,
		Team:            team,
		Verify:          verifiable(pod),
	}
}

func verifiable(pod *v1.Pod) bool {
	return pod.Labels["nais.io/attest"] == "true"
}
