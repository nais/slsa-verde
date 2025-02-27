package monitor

import (
	dptrack "github.com/nais/dependencytrack/pkg/client"
	nais_io_v1 "github.com/nais/liberator/pkg/apis/nais.io/v1"
	"slsa-verde/internal/attestation"
	"slsa-verde/internal/observability"

	v1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

type Workload struct {
	Name      string
	Namespace string
	Images    []Image
	Status    Status
	Type      string
}

type Image struct {
	Name          string
	ContainerName string
}

type Status struct {
	LastSuccessful bool
	ScaledDown     bool
}

func NewWorkload(obj any) *Workload {
	if obj == nil {
		return nil
	}

	switch obj := obj.(type) {
	case *v1.Deployment:
		deployment := obj
		images := make([]Image, 0)
		for _, c := range deployment.Spec.Template.Spec.Containers {
			images = append(images, Image{
				Name:          c.Image,
				ContainerName: c.Name,
			})
		}
		workload := &Workload{
			Name:      deployment.GetName(),
			Namespace: deployment.GetNamespace(),
			// TODO: consider using some sort of checking if the workload has labels identifying
			// TODO: an "nais application", and if so, set the type to "app" otherwise to its original type, deployment etc.
			Type:   "app",
			Images: images,
		}

		desiredReplicas := *deployment.Spec.Replicas
		if deployment.Spec.Replicas != nil &&
			deployment.Generation == deployment.Status.ObservedGeneration &&
			desiredReplicas == deployment.Status.ReadyReplicas &&
			desiredReplicas == deployment.Status.AvailableReplicas &&
			deployment.Status.UnavailableReplicas == 0 {
			workload.Status.LastSuccessful = true
			if desiredReplicas == 0 {
				workload.Status.ScaledDown = true
			}
		}
		return workload
	case *unstructured.Unstructured:
		job := &nais_io_v1.Naisjob{}
		err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, job)
		if err != nil {
			return nil
		}

		workload := &Workload{
			Name:      jobName(job),
			Namespace: job.GetNamespace(),
			Type:      "job",
			Images:    []Image{{Name: job.Spec.Image, ContainerName: jobName(job)}},
		}

		if job.Status.DeploymentRolloutStatus == "complete" {
			workload.Status.LastSuccessful = true
		}
		return workload
	default:
		return nil
	}
}

func (w *Workload) GetTag(cluster string) string {
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
		w.GetTag(cluster),
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

func (w *Workload) LastSuccessfulResource() bool {
	return w.Status.LastSuccessful
}

func (w *Workload) SetVulnerabilityCounter(hasAttestation, image, project string, p *dptrack.Project) {
	observability.WorkloadWithAttestation.WithLabelValues(w.Namespace, w.Name, w.Type, hasAttestation, image).Set(1)
	if p != nil && p.Metrics != nil {
		observability.WorkloadWithAttestationRiskScore.WithLabelValues(w.Namespace, w.Name, w.Type, project).Set(p.Metrics.InheritedRiskScore)
		observability.WorkloadWithAttestationCritical.WithLabelValues(w.Namespace, w.Name, w.Type, project).Set(float64(p.Metrics.Critical))
	}
}

func jobName(job *nais_io_v1.Naisjob) string {
	workloadName := job.Labels["app"]
	if workloadName != "" {
		return workloadName
	}

	return job.GetName()
}
