package workload

import (
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/apps/v1"
)

type DaemonSet struct {
	*Metadata
	status *v1.DaemonSetStatus
}

func NewDaemonSet(d *v1.DaemonSet, log *logrus.Entry) Workload {
	return &DaemonSet{
		Metadata: SetMetadata(
			d.GetLabels(),
			d.GetAnnotations(),
			d.Name,
			d.Namespace,
			"DaemonSet",
			log,
			d.Spec.Template.Spec.Containers,
			d.Spec.Template.Spec.InitContainers,
		),
		status: &d.Status,
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
