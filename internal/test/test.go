package test

import (
	app "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

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

func containers(images []string, name string) []v1.Container {
	c := make([]v1.Container, 0)
	for _, image := range images {
		c = append(c, v1.Container{
			Name:  name,
			Image: image,
		})
	}
	return c
}

func CreateDeployment(namespace, name string, labels map[string]string, annotations map[string]string, images ...string) *app.Deployment {
	l := merge(map[string]string{
		"nais.io/salsa-keyRef-provider": "cosign",
		"team":                          namespace,
		"app.kubernetes.io/name":        name,
	}, labels)

	replicas := int32(1)
	generation := int64(1)

	return &app.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Labels:      l,
			Annotations: annotations,
			Generation:  generation,
		},
		Status: app.DeploymentStatus{
			ObservedGeneration:  generation,
			Replicas:            replicas,
			AvailableReplicas:   replicas,
			UpdatedReplicas:     replicas,
			ReadyReplicas:       replicas,
			UnavailableReplicas: 0,
		},
		Spec: app.DeploymentSpec{
			Replicas: &replicas,
			Template: v1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Generation: 1,
					Labels:     l,
				},
				Spec: v1.PodSpec{
					Containers: containers(images, name),
				},
			},
		},
	}
}

func CreateJob(namespace, name string, labels map[string]string) *unstructured.Unstructured {
	ret := &unstructured.Unstructured{}
	ret.SetAPIVersion("nais.io/v1")
	ret.SetKind("Naisjob")
	ret.SetName(name)
	ret.SetNamespace(namespace)
	ret.SetLabels(labels)
	return ret
}

func CreateJobWithImage(namespace, name string, labels map[string]string, images ...string) *unstructured.Unstructured {
	ret := &unstructured.Unstructured{}
	ret.SetAPIVersion("nais.io/v1")
	ret.SetKind("Naisjob")
	ret.SetName(name)
	ret.SetNamespace(namespace)
	ret.Object["spec"] = map[string]interface{}{
		"image": images[0],
	}
	ret.Object["status"] = map[string]interface{}{
		"deploymentRolloutStatus": "complete",
	}
	return ret
}
