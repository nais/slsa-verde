package workload

import (
	log "github.com/sirupsen/logrus"
	appv1 "k8s.io/api/apps/v1"
)

type ReplicaSet struct {
	*Metadata
	status *appv1.ReplicaSetStatus
}

func NewReplicaSet(r *appv1.ReplicaSet, log *log.Entry) Workload {
	return &ReplicaSet{
		Metadata: SetMetadata(
			r.GetLabels(),
			r.Name,
			r.Namespace,
			"ReplicaSet",
			log,
			r.Spec.Template.Spec.Containers,
			r.Spec.Template.Spec.InitContainers,
		),
		status: &r.Status,
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

func (r *ReplicaSet) Active() bool {
	r.log.Infof("ReplicaSet %s/%s: %d/%d/%d", r.Namespace, r.Name, r.status.Replicas, r.status.AvailableReplicas, r.status.ReadyReplicas)
	return r.status.Replicas > 0 && r.status.Replicas == r.status.AvailableReplicas &&
		r.status.Replicas == r.status.ReadyReplicas
}

func (r *ReplicaSet) GetLabels() map[string]string {
	return r.Labels
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
