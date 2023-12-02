package workload

import (
	log "github.com/sirupsen/logrus"
	appv1 "k8s.io/api/apps/v1"
)

type ReplicaSet struct {
	Name       string
	Namespace  string
	Team       string
	Kind       string
	Labels     map[string]string
	Containers []Container
	Status     *appv1.ReplicaSetStatus
	Log        *log.Entry
	Verifier   *Verifier
}

func NewReplicaSet(r *appv1.ReplicaSet, log *log.Entry) Workload {
	labels := r.GetLabels()
	var c []Container
	for _, container := range r.Spec.Template.Spec.Containers {
		c = append(c, Container{
			Image: container.Image,
			Name:  container.Name,
		})
	}

	for _, container := range r.Spec.Template.Spec.InitContainers {
		c = append(c, Container{
			Image: container.Image,
			Name:  container.Name,
		})
	}
	return &ReplicaSet{
		Name:       Name(labels),
		Namespace:  r.Namespace,
		Kind:       "ReplicaSet",
		Labels:     r.Labels,
		Containers: c,
		Status:     &r.Status,
		Log:        log,
		Verifier: &Verifier{
			PredicateType:   labels[SalsaPredicateLabelKey],
			KeyRef:          labels[SalsaKeyRefLabelKey],
			KeylessProvider: labels[SalsaKeylessProviderLabelKey],
			IgnoreTLog:      labels[IgnoreTransparencyLogLabelKey],
		},
	}
}

func (r *ReplicaSet) GetName() string {
	return r.Name
}

func (r *ReplicaSet) GetTeam() string {
	return r.Labels[TeamLabelKey]
}

func (r *ReplicaSet) GetNamespace() string {
	return r.Namespace
}

func (r *ReplicaSet) GetKind() string {
	return r.Kind
}

func (r *ReplicaSet) Ready() bool {
	return r.Status.ReadyReplicas > 0 && r.Status.AvailableReplicas > 0 && r.Status.Replicas > 0
}

func (r *ReplicaSet) GetLabels() map[string]string {
	return r.Labels
}

func (r *ReplicaSet) GetContainers() []Container {
	return r.Containers
}

func (r *ReplicaSet) GetVerifier() *Verifier {
	return r.Verifier
}
