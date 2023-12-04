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
	return &StatefulSet{
		metadata: &metadata{
			Name:      setName(labels),
			Namespace: r.Namespace,
			Kind:      "StatefulSet",
			Labels:    r.Labels,
		},
		identifier: r.Name,
		containers: SetContainers(r.Spec.Template.Spec.Containers, r.Spec.Template.Spec.InitContainers),
		status:     &r.Status,
		log:        log,
		Verifier:   setVerifier(labels),
	}
}

func (s *StatefulSet) GetName() string {
	return s.Name
}

func (s *StatefulSet) GetTeam() string {
	return s.labels[TeamLabelKey]
}

func (s *StatefulSet) GetNamespace() string {
	return s.Namespace
}

func (s *StatefulSet) GetKind() string {
	return s.Kind
}

func (s *StatefulSet) Active() bool {
	return s.status.ReadyReplicas > 0 && s.status.AvailableReplicas > 0 && s.status.Replicas > 0
}

func (s *StatefulSet) GetLabels() map[string]string {
	return s.labels
}

func (s *StatefulSet) GetContainers() []Container {
	return s.containers
}

func (s *StatefulSet) GetVerifier() *Verifier {
	return s.Verifier
}

func (s *StatefulSet) GetIdentifier() string {
	return s.identifier
}
