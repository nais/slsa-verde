package workload

import (
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/apps/v1"
)

type DaemonSet struct {
	*metadata
	containers []Container
	status     *v1.DaemonSetStatus
	log        *logrus.Entry
	identifier string
	Verifier   *Verifier
}

func NewDaemonSet(d *v1.DaemonSet, log *logrus.Entry) Workload {
	labels := d.GetLabels()
	return &DaemonSet{
		metadata: &metadata{
			Name:      setName(labels),
			Namespace: d.Namespace,
			Kind:      "DaemonSet",
			Labels:    d.Labels,
		},
		identifier: d.Name,
		containers: SetContainers(d.Spec.Template.Spec.Containers, d.Spec.Template.Spec.InitContainers),
		status:     &d.Status,
		log:        log,
		Verifier:   setVerifier(labels),
	}
}

func (d *DaemonSet) GetName() string {
	return d.Name
}

func (d *DaemonSet) GetTeam() string {
	return d.Labels[TeamLabelKey]
}

func (d *DaemonSet) GetNamespace() string {
	return d.Namespace
}

func (d *DaemonSet) GetKind() string {
	return d.Kind
}

func (d *DaemonSet) Active() bool {
	return d.status.NumberReady > 0
}

func (d *DaemonSet) GetLabels() map[string]string {
	return d.Labels
}

func (d *DaemonSet) GetContainers() []Container {
	return d.containers
}

func (d *DaemonSet) GetVerifier() *Verifier {
	return d.Verifier
}

func (d *DaemonSet) GetIdentifier() string {
	return d.identifier
}
