package test

import (
	app "k8s.io/api/apps/v1"
	batch "k8s.io/api/batch/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

func CreateJob(namespace, name string, labels map[string]string) *batch.Job {
	return &batch.Job{
		ObjectMeta: metav1.ObjectMeta{
			Labels:    labels,
			Name:      name,
			Namespace: namespace,
		},
	}
}

func CreateJobWithContainer(namespace, name string, labels map[string]string, images ...string) *batch.Job {
	job := CreateJob(namespace, name, labels)
	l := merge(map[string]string{
		"nais.io/salsa-keyRef-provider": "cosign",
		"team":                          namespace,
		"app.kubernetes.io/name":        name,
	}, labels)

	job.Spec = batch.JobSpec{
		Template: v1.PodTemplateSpec{
			ObjectMeta: metav1.ObjectMeta{
				Labels: l,
			},
			Spec: v1.PodSpec{
				Containers: containers(images, name),
			},
		},
	}

	return job
}
