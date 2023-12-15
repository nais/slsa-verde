package workload

import (
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/batch/v1"
)

type Job struct {
	*Metadata
	status *v1.JobStatus
}

func NewJob(j *v1.Job, log *logrus.Entry) Workload {
	return &Job{
		Metadata: SetMetadata(
			j.GetLabels(),
			j.GetAnnotations(),
			j.Name,
			j.Namespace,
			"Job",
			log,
			j.Spec.Template.Spec.Containers,
			j.Spec.Template.Spec.InitContainers,
		),
		status: &j.Status,
	}
}

func (j *Job) GetName() string {
	return j.Name
}

func (j *Job) GetTeam() string {
	return j.Labels[TeamLabelKey]
}

func (j *Job) GetNamespace() string {
	return j.Namespace
}

func (j *Job) GetKind() string {
	return j.Kind
}

func (j *Job) Active() bool {
	return j.status.Succeeded > 0
}

func (j *Job) GetLabels() map[string]string {
	return j.Labels
}

func (j *Job) GetContainers() []Container {
	return j.containers
}

func (j *Job) GetVerifier() *Verifier {
	return j.Verifier
}

func (j *Job) GetIdentifier() string {
	return j.identifier
}
