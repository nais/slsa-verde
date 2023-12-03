package workload

import (
	log "github.com/sirupsen/logrus"
	appv1 "k8s.io/api/apps/v1"
)

type StatefulSet struct {
	*metadata
	labels     map[string]string
	containers []Container
	status     *appv1.StatefulSetStatus
	log        *log.Entry
	Verifier   *Verifier
	identifier string
}

func NewStatefulSet(r *appv1.StatefulSet, log *log.Entry) Workload {
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
	return &StatefulSet{
		metadata: &metadata{
			Name:      setName(labels),
			Namespace: r.Namespace,
			Kind:      "StatefulSet",
			Labels:    r.Labels,
		},
		identifier: r.Name,
		containers: c,
		status:     &r.Status,
		log:        log,
		Verifier:   setVerifier(labels),
	}
}

func (r *StatefulSet) GetName() string {
	return r.Name
}

func (r *StatefulSet) GetTeam() string {
	return r.labels[TeamLabelKey]
}

func (r *StatefulSet) GetNamespace() string {
	return r.Namespace
}

func (r *StatefulSet) GetKind() string {
	return r.Kind
}

func (r *StatefulSet) Active() bool {
	return r.status.ReadyReplicas > 0 && r.status.AvailableReplicas > 0 && r.status.Replicas > 0
}

func (r *StatefulSet) GetLabels() map[string]string {
	return r.labels
}

func (r *StatefulSet) GetContainers() []Container {
	return r.containers
}

func (r *StatefulSet) GetVerifier() *Verifier {
	return r.Verifier
}

func (r *StatefulSet) GetIdentifier() string {
	return r.identifier
}