package monitor

import (
	"strings"

	dptrack "github.com/nais/dependencytrack/pkg/client"

	v1 "k8s.io/api/apps/v1"
	batch "k8s.io/api/batch/v1"
	core "k8s.io/api/core/v1"
	"picante/internal/attestation"
)

type Workload struct {
	Name       string
	Namespace  string
	Containers []core.Container
	Status     Status
	Type       string
}

type Status struct {
	LastSuccessful bool
}

func NewWorkload(obj any) *Workload {
	workload := &Workload{}
	if d, ok := obj.(*v1.Deployment); ok {
		workload = &Workload{
			Name:       d.GetName(),
			Namespace:  d.GetNamespace(),
			Type:       "app",
			Containers: d.Spec.Template.Spec.Containers,
		}

		for _, condition := range d.Status.Conditions {
			if condition.Type == "Progressing" && condition.Status == "True" && condition.Reason == "NewReplicaSetAvailable" {
				workload.Status.LastSuccessful = true
			}
		}
	}

	if j, ok := obj.(*batch.Job); ok {
		workload = &Workload{
			Name:       jobName(j),
			Namespace:  j.GetNamespace(),
			Type:       "job",
			Containers: j.Spec.Template.Spec.Containers,
		}
		for _, condition := range j.Status.Conditions {
			if condition.Type == "Complete" && condition.Status == "True" {
				workload.Status.LastSuccessful = true
			}
		}
	}

	return workload
}

func (w *Workload) getTag(cluster string) string {
	return dptrack.WorkloadTagPrefix.With(cluster + "|" + w.Namespace + "|" + w.Type + "|" + w.Name)
}

func (w *Workload) initWorkloadTags(metadata *attestation.ImageMetadata, cluster, projectName, projectVersion string) []string {
	return []string{
		dptrack.ProjectTagPrefix.With(projectName),
		dptrack.ImageTagPrefix.With(metadata.Image),
		dptrack.VersionTagPrefix.With(projectVersion),
		dptrack.DigestTagPrefix.With(metadata.Digest),
		dptrack.RekorTagPrefix.With(metadata.RekorLogIndex),
		dptrack.EnvironmentTagPrefix.With(cluster),
		dptrack.TeamTagPrefix.With(w.Namespace),
		w.getTag(cluster),
	}
}

func jobName(job *batch.Job) string {
	workloadName := job.Labels["app"]
	if workloadName != "" {
		return workloadName
	}

	// keep everything before the last dash
	beforeLastDash := strings.LastIndex(job.GetName(), "-")
	if beforeLastDash == -1 {
		// no dash, use the whole name
		workloadName = job.GetName()
	} else {
		// use everything before the last dash
		workloadName = job.GetName()[:beforeLastDash]
	}
	return workloadName
}
