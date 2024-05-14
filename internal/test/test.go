package test

import (
	app "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func CreatePod(namespace, name string, labels map[string]string, images ...string) *v1.Pod {
	c := make([]v1.Container, 0)
	initc := make([]v1.Container, 0)
	for _, image := range images {
		c = append(c, v1.Container{
			Name:  name,
			Image: image,
		})
		initc = append(initc, v1.Container{
			Image: image,
			Name:  name,
		})
	}
	l := merge(map[string]string{
		"nais.io/salsa-keyRef-provider": "cosign",
		"team":                          namespace,
		"app.kubernetes.io/name":        name,
	}, labels)
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    l,
		},
		Spec: v1.PodSpec{
			Containers:     c,
			InitContainers: initc,
		},
	}
}

func merge(map1, map2 map[string]string) map[string]string {
	mergedMap := make(map[string]string)
	for key, value := range map1 {
		mergedMap[key] = value
	}
	for key, value := range map2 {
		mergedMap[key] = value
	}
	return mergedMap
}

func CreateDeployment(namespace, name string, labels map[string]string, annotations map[string]string, images ...string) *app.Deployment {
	c := make([]v1.Container, 0)
	for _, image := range images {
		c = append(c, v1.Container{
			Name:  name,
			Image: image,
		})
	}
	l := merge(map[string]string{
		"nais.io/salsa-keyRef-provider": "cosign",
		"team":                          namespace,
		"app.kubernetes.io/name":        name,
	}, labels)

	replicas := int32(1)

	return &app.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Labels:      l,
			Annotations: annotations,
		},
		Spec: app.DeploymentSpec{
			Replicas: &replicas,
			Template: v1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: l,
				},
				Spec: v1.PodSpec{
					Containers: c,
				},
			},
		},
	}
}
