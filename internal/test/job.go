package test

import (
	batch "k8s.io/api/batch/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func CreateJob(name string, labels map[string]string) *batch.Job {
	return &batch.Job{
		ObjectMeta: v1.ObjectMeta{
			Labels: labels,
			Name:   name,
		},
	}
}
