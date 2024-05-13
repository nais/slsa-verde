package workload

import (
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/apps/v1"
)

type Deployment struct {
	log *logrus.Entry
	*Metadata
	status *v1.DeploymentStatus
}

func NewDeployment(d *v1.Deployment, log *logrus.Entry) Workload {
	return &Deployment{
		Metadata: SetMetadata(
			d.GetLabels(),
			d.GetAnnotations(),
			d.Name,
			d.Namespace,
			"Deployment",
			log,
			d.Spec.Template.Spec.Containers,
			d.Spec.Template.Spec.InitContainers,
		),
		status: &d.Status,
		log:    log,
	}
}

func (d *Deployment) GetName() string {
	return d.Name
}

func (d *Deployment) GetTeam() string {
	return d.Labels[TeamLabelKey]
}

func (d *Deployment) GetNamespace() string {
	return d.Namespace
}

func (d *Deployment) GetKind() string {
	return d.Kind
}

func (d *Deployment) Active() bool {

	d.log.Debug(d.identifier, ":", d.status.AvailableReplicas)

	return d.status.AvailableReplicas > 0
}

func (d *Deployment) GetLabels() map[string]string {
	return d.Labels
}

func (d *Deployment) GetContainers() []Container {
	return d.containers
}

func (d *Deployment) GetVerifier() *Verifier {
	return d.Verifier
}

func (d *Deployment) GetIdentifier() string {
	return d.identifier
}
