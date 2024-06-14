package monitor

import (
	"strings"

	dptrack "github.com/nais/dependencytrack/pkg/client"
	nais_io_v1 "github.com/nais/liberator/pkg/apis/nais.io/v1"

	"slsa-verde/internal/attestation"

	v1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

type Workload struct {
	Name      string
	Namespace string
	Images    []string
	Status    Status
	Type      string
}

type Status struct {
	LastSuccessful bool
}

func NewWorkload(obj any) *Workload {
	workload := &Workload{}
	if d, ok := obj.(*v1.Deployment); ok {
		images := make([]string, 0)
		for _, c := range d.Spec.Template.Spec.Containers {
			images = append(images, c.Image)
		}
		workload = &Workload{
			Name:      d.GetName(),
			Namespace: d.GetNamespace(),
			Type:      "app",
			Images:    images,
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
		return workload
	}

	job := &nais_io_v1.Naisjob{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.(*unstructured.Unstructured).Object, job); err == nil {
		workload := &Workload{
			Name:      job.GetName(),
			Namespace: job.GetNamespace(),
			Type:      "job",
			Images:    []string{job.Spec.Image},
		}

		if job.Status.DeploymentRolloutStatus == "complete" {
			workload.Status.LastSuccessful = true
		}
		return workload
	}

	return nil
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

func jobName(job *nais_io_v1.Naisjob) string {
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
