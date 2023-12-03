package workload

import (
	log "github.com/sirupsen/logrus"
	appv1 "k8s.io/api/apps/v1"
)

type StatefulSet struct {
	*metadata
	Labels     map[string]string
	Containers []Container
	Status     *appv1.StatefulSetStatus
	Log        *log.Entry
	Verifier   *Verifier
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
		Containers: c,
		Status:     &r.Status,
		Log:        log,
		Verifier:   setVerifier(labels),
	}
}

func (r *StatefulSet) GetName() string {
	return r.Name
}

func (r *StatefulSet) GetTeam() string {
	return r.Labels[TeamLabelKey]
}

func (r *StatefulSet) GetNamespace() string {
	return r.Namespace
}

func (r *StatefulSet) GetKind() string {
	return r.Kind
}

func (r *StatefulSet) Active() bool {
	return r.Status.ReadyReplicas > 0 && r.Status.AvailableReplicas > 0 && r.Status.Replicas > 0
}

func (r *StatefulSet) GetLabels() map[string]string {
	return r.Labels
}

func (r *StatefulSet) GetContainers() []Container {
	return r.Containers
}

func (r *StatefulSet) GetVerifier() *Verifier {
	return r.Verifier
}
