package workload

import (
	log "github.com/sirupsen/logrus"
	appv1 "k8s.io/api/apps/v1"
)

type StatefulSet struct {
	*Metadata
	status *appv1.StatefulSetStatus
}

func NewStatefulSet(s *appv1.StatefulSet, log *log.Entry) Workload {
	return &StatefulSet{
		Metadata: SetMetadata(
			s.GetLabels(),
			s.Name,
			s.Namespace,
			"StatefulSet",
			log,
			s.Spec.Template.Spec.Containers,
			s.Spec.Template.Spec.InitContainers,
		),
		status: &s.Status,
	}
}

func (s *StatefulSet) GetName() string {
	return s.Name
}

func (s *StatefulSet) GetTeam() string {
	return s.Labels[TeamLabelKey]
}

func (s *StatefulSet) GetNamespace() string {
	return s.Namespace
}

func (s *StatefulSet) GetKind() string {
	return s.Kind
}

func (s *StatefulSet) Active() bool {
	return s.status.Replicas > 0 && s.status.Replicas == s.status.AvailableReplicas &&
		s.status.Replicas == s.status.ReadyReplicas
}

func (s *StatefulSet) GetLabels() map[string]string {
	return s.Labels
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
