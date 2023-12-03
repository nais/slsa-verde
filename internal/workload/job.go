package workload

import (
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/batch/v1"
)

type Job struct {
	*metadata
	Containers []Container
	Status     *v1.JobStatus
	Log        *logrus.Entry
	Verifier   *Verifier
}

func NewJob(job *v1.Job, log *logrus.Entry) Workload {
	labels := job.GetLabels()
	var c []Container
	for _, container := range job.Spec.Template.Spec.Containers {
		c = append(c, Container{
			Image: container.Image,
			Name:  container.Name,
		})
	}

	for _, container := range job.Spec.Template.Spec.InitContainers {
		c = append(c, Container{
			Image: container.Image,
			Name:  container.Name,
		})
	}
	return &Job{
		metadata: &metadata{
			Name:      setName(labels),
			Namespace: job.Namespace,
			Kind:      "Job",
			Labels:    job.Labels,
		},
		Containers: c,
		Status:     &job.Status,
		Log:        log,
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
	return j.Status.Succeeded > 0
}

func (j *Job) GetLabels() map[string]string {
	return j.Labels
}

func (j *Job) GetContainers() []Container {
	return j.Containers
}

func (j *Job) GetVerifier() *Verifier {
	return j.Verifier
}
