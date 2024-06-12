package monitor

import (
	"strings"

	dptrack "github.com/nais/dependencytrack/pkg/client"

	v1 "k8s.io/api/apps/v1"
	batch "k8s.io/api/batch/v1"
	core "k8s.io/api/core/v1"
	"slsa-verde/internal/attestation"
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

		desiredReplicas := *d.Spec.Replicas
		if d.Spec.Replicas != nil &&
			d.Generation == d.Status.ObservedGeneration &&
			desiredReplicas == d.Status.Replicas &&
			desiredReplicas == d.Status.ReadyReplicas &&
			desiredReplicas == d.Status.AvailableReplicas &&
			desiredReplicas == d.Status.UpdatedReplicas &&
			d.Status.UnavailableReplicas == 0 {
			workload.Status.LastSuccessful = true
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
	tags := []string{
		dptrack.ProjectTagPrefix.With(projectName),
		dptrack.ImageTagPrefix.With(metadata.Image),
		dptrack.VersionTagPrefix.With(projectVersion),
		dptrack.DigestTagPrefix.With(metadata.Digest),
		dptrack.EnvironmentTagPrefix.With(cluster),
		dptrack.TeamTagPrefix.With(w.Namespace),
		w.getTag(cluster),
	}
	if metadata.RekorMetadata != nil {
		tags = append(tags, dptrack.RekorTagPrefix.With(metadata.RekorMetadata.LogIndex))
		tags = append(tags, dptrack.RekorBuildTriggerTagPrefix.With(metadata.RekorMetadata.BuildTrigger))
		tags = append(tags, dptrack.RekorOIDCIssuerTagPrefix.With(metadata.RekorMetadata.OIDCIssuer))
		tags = append(tags, dptrack.RekorGitHubWorkflowNameTagPrefix.With(metadata.RekorMetadata.GitHubWorkflowName))
		tags = append(tags, dptrack.RekorGitHubWorkflowRefTagPrefix.With(metadata.RekorMetadata.GitHubWorkflowRef))
		tags = append(tags, dptrack.RekorGitHubWorkflowSHATagPrefix.With(metadata.RekorMetadata.GitHubWorkflowSHA))
		tags = append(tags, dptrack.RekorSourceRepositoryOwnerURITagPrefix.With(metadata.RekorMetadata.SourceRepositoryOwnerURI))
		tags = append(tags, dptrack.RekorBuildConfigURITagPrefix.With(metadata.RekorMetadata.BuildConfigURI))
		tags = append(tags, dptrack.RekorRunInvocationURITagPrefix.With(metadata.RekorMetadata.RunInvocationURI))
		tags = append(tags, dptrack.RekorIntegratedTimeTagPrefix.With(metadata.RekorMetadata.IntegratedTime))
	}
	return tags
}

func (w *Workload) isJob() bool {
	return w.Type == "job"
}

func jobName(job *batch.Job) string {
	workloadName := job.Labels["app"]
	if workloadName != "" {
		return workloadName
	}

	// TODO bug when job id deployed manually or using dash
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
