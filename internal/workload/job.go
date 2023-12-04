package workload

import (
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/batch/v1"
)

type Job struct {
	*metadata
	containers []Container
	status     *v1.JobStatus
	log        *logrus.Entry
	identifier string
	Verifier   *Verifier
}

func NewJob(job *v1.Job, log *logrus.Entry) Workload {
	labels := job.GetLabels()
	return &Job{
		metadata: &metadata{
			Name:      setName(labels),
			Namespace: job.Namespace,
			Kind:      "Job",
			Labels:    job.Labels,
		},
		identifier: job.Name,
		containers: SetContainers(job.Spec.Template.Spec.Containers, job.Spec.Template.Spec.InitContainers),
		status:     &job.Status,
		log:        log,
		Verifier:   setVerifier(labels),
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
