package workload

import (
	log "github.com/sirupsen/logrus"
	appv1 "k8s.io/api/apps/v1"
)

type ReplicaSet struct {
	*metadata
	labels     map[string]string
	containers []Container
	status     *appv1.ReplicaSetStatus
	log        *log.Entry
	identifier string
	Verifier   *Verifier
}

func NewReplicaSet(r *appv1.ReplicaSet, log *log.Entry) Workload {
	labels := r.GetLabels()
	return &ReplicaSet{
		metadata: &metadata{
			Name:      setName(labels),
			Namespace: r.Namespace,
			Kind:      "ReplicaSet",
			Labels:    r.Labels,
		},
		identifier: r.Name,
		containers: SetContainers(r.Spec.Template.Spec.Containers, r.Spec.Template.Spec.InitContainers),
		status:     &r.Status,
		log:        log,
		Verifier:   setVerifier(labels),
	}
}

func (r *ReplicaSet) GetName() string {
	return r.Name
}

func (r *ReplicaSet) GetTeam() string {
	return r.labels[TeamLabelKey]
}

func (r *ReplicaSet) GetNamespace() string {
	return r.Namespace
}

func (r *ReplicaSet) GetKind() string {
	return r.Kind
}

func (r *ReplicaSet) Active() bool {
	return r.status.ReadyReplicas > 0 && r.status.AvailableReplicas > 0 && r.status.Replicas > 0
}

func (r *ReplicaSet) GetLabels() map[string]string {
	return r.labels
}

func (r *ReplicaSet) GetContainers() []Container {
	return r.containers
}

func (r *ReplicaSet) GetVerifier() *Verifier {
	return r.Verifier
}

func (r *ReplicaSet) GetIdentifier() string {
	return r.identifier
}
