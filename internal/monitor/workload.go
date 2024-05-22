package monitor

import (
	v1 "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	"picante/internal/attestation"
)

type Workload struct {
	Name       string
	Namespace  string
	Containers []core.Container
	Conditions []Conditions
	Type       string
}

type Conditions struct {
	Type   string
	Status string
	Reason string
}

func NewWorkload(obj any) *Workload {
	if d, ok := obj.(*v1.Deployment); ok {
		conditions := make([]Conditions, 0)
		for _, condition := range d.Status.Conditions {
			conditions = append(conditions, Conditions{
				Type:   string(condition.Type),
				Status: string(condition.Status),
				Reason: condition.Reason,
			})
		}
		return &Workload{
			Name:       d.GetName(),
			Namespace:  d.GetNamespace(),
			Type:       "app",
			Containers: d.Spec.Template.Spec.Containers,
			Conditions: conditions,
		}
	}
	return nil
}

func (w *Workload) getWorkloadStatus() bool {
	status := false
	switch w.Type {
	case "app":
		for _, condition := range w.Conditions {
			if condition.Type == "Progressing" && condition.Status == "True" && condition.Reason == "NewReplicaSetAvailable" {
				status = true
			}
		}
	}
	return status
}

func (w *Workload) getTag(cluster string) string {
	return WorkloadTagPrefix + cluster + "|" + w.Namespace + "|" + w.Type + "|" + w.Name
}

func (w *Workload) initWorkloadTags(metadata *attestation.ImageMetadata, cluster, projectName, projectVersion string) []string {
	return []string{
		"project:" + projectName,
		"image:" + metadata.Image,
		"version:" + projectVersion,
		"digest:" + metadata.Digest,
		"rekor:" + metadata.RekorLogIndex,
		"environment:" + cluster,
		"team:" + w.Namespace,
		w.getTag(cluster),
	}
}
