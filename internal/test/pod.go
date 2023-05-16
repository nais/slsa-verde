package test

import (
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
