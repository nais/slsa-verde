package monitor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/nais/v13s/pkg/api/vulnerabilities/management"

	"github.com/nais/dependencytrack/pkg/client"
	"github.com/nais/v13s/pkg/api/vulnerabilities"
	"github.com/sirupsen/logrus"

	"slsa-verde/internal/attestation"
	"slsa-verde/internal/observability"
)

const (
	ErrProjectAlreadyExists = "status 409"
)

type Config struct {
	Client      client.Client
	vulnzClient vulnerabilities.Client
	Cluster     string
	verifier    attestation.Verifier
	logger      *logrus.Entry
	ctx         context.Context
}

func NewMonitor(ctx context.Context, client client.Client, vulnzClient vulnerabilities.Client, verifier attestation.Verifier, cluster string) *Config {
	return &Config{
		Client:      client,
		vulnzClient: vulnzClient,
		Cluster:     cluster,
		verifier:    verifier,
		logger:      logrus.WithField("package", "monitor"),
		ctx:         ctx,
	}
}

func (c *Config) OnDelete(obj any) {
	log := c.logger.WithField("event", "delete")

	workload := NewWorkload(obj)
	if workload == nil {
		log.Debug("not a verified workload")
		return
	}

	l := log.WithFields(logrus.Fields{
		"workload":  workload.Name,
		"namespace": workload.Namespace,
		"type":      workload.Type,
	})

	projects, err := c.retrieveProjects(workload.GetTag(c.Cluster))
	if err != nil {
		l.Warnf("retrieve projects: %v", err)
		return
	}

	ll := l.WithFields(logrus.Fields{
		"workload-tag": workload.GetTag(c.Cluster),
	})

	if err := c.tidyWorkloadProjects(projects, workload, ll); err != nil {
		l.Warnf("cleanup workload: %v", err)
	}
}

func (c *Config) OnUpdate(past any, present any) {
	log := c.logger.WithField("event", "update")

	workload := NewWorkload(present)
	if workload == nil {
		log.Debug("not verified workload")
		return
	}

	pastWorkload := NewWorkload(past)
	if pastWorkload == nil {
		log.Debug("not verified workload")
		return
	}

	l := log.WithFields(logrus.Fields{
		"workload":  workload.Name,
		"namespace": workload.Namespace,
		"type":      workload.Type,
	})

	if workload.LastSuccessfulResource() && !pastWorkload.LastSuccessfulResource() {
		if err := c.verifyWorkloadContainers(c.ctx, workload, l); err != nil {
			l.Warnf("verify attestation: %v", err)
		}
	}
}

func (c *Config) OnAdd(obj any) {
	log := c.logger.WithField("event", "add")

	workload := NewWorkload(obj)
	if workload == nil {
		log.Debug("not a verified workload")
		return
	}

	l := log.WithFields(logrus.Fields{
		"workload":  workload.Name,
		"namespace": workload.Namespace,
		"type":      workload.Type,
	})

	if !workload.LastSuccessfulResource() {
		l.Debug("workload not successful")
		return
	}

	if err := c.verifyWorkloadContainers(c.ctx, workload, l); err != nil {
		l.Warnf("verify attestation: %v", err)
		return
	}
}

func (c *Config) verifyWorkloadContainers(ctx context.Context, workload *Workload, log *logrus.Entry) error {
	for _, image := range workload.Images {
		var err error
		if workload.Status.ScaledDown {
			if err = c.scaledDown(workload, log); err != nil {
				return err
			}
			continue
		}
		if err = c.verifyImage(ctx, workload, image, log); err != nil {
			return err
		}
	}
	return nil
}

func (c *Config) scaledDown(workload *Workload, log *logrus.Entry) error {
	l := log.WithFields(logrus.Fields{
		"event":     "scale-down",
		"workload":  workload.Name,
		"namespace": workload.Namespace,
		"type":      workload.Type,
	})
	// Deployment is scaled down, we need to look for the workload tag in all found projects
	p, err := c.retrieveProjects(workload.GetTag(c.Cluster))
	if err != nil {
		return err
	}

	if len(p) == 0 {
		l.Debug("no projects found for workload tag")
		return nil
	}

	if err := c.tidyWorkloadProjects(p, workload, log); err != nil {
		return err
	}
	return nil
}

func (c *Config) verifyImage(ctx context.Context, workload *Workload, image Image, log *logrus.Entry) error {
	var err error
	workloadTag := workload.GetTag(c.Cluster)
	projectName := getProjectName(image.Name)
	projectVersion := getProjectVersion(image.Name)
	project, err := c.Client.GetProject(ctx, projectName, projectVersion)
	if err != nil {
		return err
	}

	l := log.WithFields(logrus.Fields{
		"project":         projectName,
		"project-version": projectVersion,
		"image":           image,
		"workload-tag":    workloadTag,
		"cluster":         c.Cluster,
	})

	if project != nil {
		if err = c.updateExistingProjectTags(workload, project, image.Name, l); err != nil {
			l.Warnf("update project tags: %v)", err)
		}
		// filter projects with the same workload tag and different version
		projects := c.filterProjects(client.ProjectTagPrefix.With(projectName), project)
		// cleanup projects with the same workload tag
		if err = c.tidyWorkloadProjects(projects, workload, l); err != nil {
			return err
		}
		if err = c.RegisterWorkload(projectName, projectVersion, workload); err != nil {
			log.Warnf("register workload: %v", err)
		}
	} else {
		var metadata *attestation.ImageMetadata
		metadata, err = c.verifier.Verify(c.ctx, image.Name)
		if err != nil {
			workload.SetVulnerabilityCounter("false", image.Name, projectName, nil)
			_ = c.RegisterWorkload(projectName, projectVersion, workload, image.ContainerName)
			if strings.Contains(err.Error(), attestation.ErrNoAttestation) {
				l.Debugf("skipping, %v", err)
				if err != nil {
					log.Warnf("register workload: %v", err)
				}
				return nil
				// continue
			}
			l.Warnf("verify attestation error, skipping: %v", err)
			return err
			// continue
		}

		if metadata.Statement == nil {
			l.Warn("metadata is empty, skipping")
			return nil
			// continue
		}

		log.WithFields(logrus.Fields{
			"digest": metadata.Digest,
		})

		l.Debug("project does not exist, updating workload ...")
		var projects []*client.Project
		projects, err = c.retrieveProjects(workloadTag)
		if err != nil {
			l.Warnf("retrieve project, skipping %v", err)
			return err
		}

		if err = c.tidyWorkloadProjects(projects, workload, l); err != nil {
			return err
		}

		tags := workload.initWorkloadTags(metadata, c.Cluster, projectName, projectVersion)
		var createdP *client.Project
		createdP, err = c.Client.CreateProject(ctx, projectName, projectVersion, getGroup(projectName), tags)
		if err != nil {
			if !strings.Contains(err.Error(), ErrProjectAlreadyExists) {
				return err
			}

			// This is to handle the case when another slsa-verde instance created the same project
			// before this instance could create it.
			// In this case, we update the existing project with the workload tag.
			if err = c.updateExistingProjectTags(workload, createdP, image.Name, l); err != nil {
				return fmt.Errorf("update project tags, when the project already exists: %w", err)
			}
			l.Info("project already exists, updated with workload tag")
			return nil
		}

		if err = c.uploadSBOMToProject(ctx, metadata, projectName, createdP.Uuid, projectVersion); err != nil {
			return err
		}
		ll := l.WithFields(logrus.Fields{
			"project-uuid": createdP.Uuid,
		})
		ll.Info("project created with workload tag")

		if err = c.Client.TriggerAnalysis(ctx, createdP.Uuid); err != nil {
			ll.Warnf("trigger analysis: %v", err)
		}

		if err = c.RegisterWorkloadWithMetadata(createdP.Name, createdP.Version, workload, metadata); err != nil {
			ll.Warnf("register workload: %v", err)
		}

		workload.SetVulnerabilityCounter("true", image.Name, projectName, createdP)
	}
	return nil
}

func (c *Config) RegisterWorkloadWithMetadata(projectName, projectVersion string, workload *Workload, m *attestation.ImageMetadata) error {
	if c.vulnzClient == nil {
		c.logger.Debug("vulnerabilities client is not enabled")
		return nil
	}

	var workloadMetadata *management.Metadata

	if m != nil {
		workloadMetadata = buildMetadataFromImageMetadata(m)
	}

	_, err := c.vulnzClient.RegisterWorkload(c.ctx, &management.RegisterWorkloadRequest{
		Cluster:      c.Cluster,
		Namespace:    workload.Namespace,
		Workload:     workload.Name,
		WorkloadType: workload.Type,
		ImageName:    projectName,
		ImageTag:     projectVersion,
		Metadata:     workloadMetadata,
	})

	return err
}

func buildMetadataFromImageMetadata(m *attestation.ImageMetadata) *management.Metadata {
	return &management.Metadata{
		Labels: map[string]string{
			"digest":                            m.Digest,
			"rekor-log-index":                   m.RekorMetadata.LogIndex,
			"rekor-build-trigger":               m.RekorMetadata.BuildTrigger,
			"rekor-oidc-issuer":                 m.RekorMetadata.OIDCIssuer,
			"rekor-github-workflow-name":        m.RekorMetadata.GitHubWorkflowName,
			"rekor-github-workflow-ref":         m.RekorMetadata.GitHubWorkflowRef,
			"rekor-github-workflow-sha":         m.RekorMetadata.GitHubWorkflowSHA,
			"rekor-source-repository-owner-uri": m.RekorMetadata.SourceRepositoryOwnerURI,
			"rekor-build-config-uri":            m.RekorMetadata.BuildConfigURI,
			"rekor-run-invocation-uri":          m.RekorMetadata.RunInvocationURI,
			"rekor-integrated-time":             m.RekorMetadata.IntegratedTime,
		},
	}
}

func (c *Config) RegisterWorkload(projectName, projectVersion string, workload *Workload, containerName ...string) error {
	if c.vulnzClient == nil {
		c.logger.Debug("vulnerabilities client is not enabled")
		return nil
	}

	// Use containerName if provided, otherwise fallback to workload.Name
	workloadName := workload.Name
	if len(containerName) > 0 && containerName[0] != "" {
		workloadName = containerName[0]
	}

	_, err := c.vulnzClient.RegisterWorkload(c.ctx, &management.RegisterWorkloadRequest{
		Cluster:      c.Cluster,
		Namespace:    workload.Namespace,
		Workload:     workloadName,
		WorkloadType: workload.Type,
		ImageName:    projectName,
		ImageTag:     projectVersion,
	})

	return err
}

func (c *Config) updateExistingProjectTags(workload *Workload, project *client.Project, image string, log *logrus.Entry) error {
	var err error
	projectName := getProjectName(image)
	projectVerion := getProjectVersion(image)
	if project == nil {
		project, err = c.Client.GetProject(c.ctx, projectName, projectVerion)
		if err != nil {
			return err
		}
	}

	if project == nil {
		return fmt.Errorf("project not found")
	}

	log.Debug("project found, updating workload...")
	workloadTag := workload.GetTag(c.Cluster)
	tags := NewTags()
	tags.ArrangeByPrefix(project.Tags)
	attest := HasAttestation(project)

	if tags.addWorkloadTag(workloadTag) {
		_, err = c.Client.UpdateProject(c.ctx, project.Uuid, project.Name, project.Version, project.Group, tags.GetAllTags())
		if err != nil {
			return err
		}
		ll := log.WithFields(logrus.Fields{
			"project-uuid": project.Uuid,
		})
		ll.Info("project tagged with workload")
	}
	workload.SetVulnerabilityCounter(strconv.FormatBool(attest), image, projectName, project)
	return nil
}

func getProjectName(containerImage string) string {
	if strings.Contains(containerImage, "@") {
		return strings.Split(containerImage, "@")[0]
	}
	return strings.Split(containerImage, ":")[0]
}

func getProjectVersion(image string) string {
	if !strings.Contains(image, "@") {
		i := strings.LastIndex(image, ":")
		return image[i+1:]
	}

	return handleImageDigest(image)
}

func handleImageDigest(image string) string {
	// format: <image>@<digest>
	imageArray := strings.Split(image, "@")
	i := strings.LastIndex(imageArray[0], ":")
	// format: <image>:<tag>@<digest>
	if i != -1 {
		return imageArray[0][i+1:] + "@" + imageArray[1]
	}
	return imageArray[1]
}

func (c *Config) filterProjects(tag string, project *client.Project) []*client.Project {
	projects, err := c.retrieveProjects(tag)
	if err != nil {
		c.logger.Warnf("retrieve projects: %v", err)
		return nil
	}
	var filteredProjects []*client.Project
	for _, p := range projects {
		if p.Version != project.Version {
			filteredProjects = append(filteredProjects, p)
		}
	}
	return filteredProjects
}

func (c *Config) retrieveProjects(tagName string) ([]*client.Project, error) {
	tag := url.QueryEscape(tagName)
	projects, err := c.Client.GetProjectsByTag(c.ctx, tag)
	if err != nil {
		return nil, fmt.Errorf("getting projects from DependencyTrack: %w", err)
	}

	if len(projects) == 0 {
		return nil, nil
	}

	var filteredProjects []*client.Project

	// TODO: remove this
	// Filter out projects with project name prefix: "europe-north1-docker.pkg.dev/nais-io/nais/images/wonderwall"
	for _, p := range projects {
		if !strings.Contains(p.Name, "europe-north1-docker.pkg.dev/nais-io/nais/images/wonderwall") {
			filteredProjects = append(filteredProjects, p)
		}
	}

	return filteredProjects, nil
}

func (c *Config) tidyWorkloadProjects(projects []*client.Project, workload *Workload, log *logrus.Entry) error {
	var err error
	workloadTag := workload.GetTag(c.Cluster)
	for _, p := range projects {
		tags := NewTags()
		tags.ArrangeByPrefix(p.Tags)
		image := tags.GetImageTag()
		attest := HasAttestation(p)

		l := log.WithFields(logrus.Fields{
			"image":           image,
			"has-attestation": attest,
		})

		if IsThisWorkload(tags, workloadTag) {
			if err = c.Client.DeleteProject(c.ctx, p.Uuid); err != nil {
				l.Warnf("delete project: %v", err)
				continue
			}
			l.Info("project deleted")
			observability.WorkloadWithAttestation.DeleteLabelValues(workload.Namespace, workload.Name, workload.Type, strconv.FormatBool(attest), image)
		} else if tags.HasWorkload(workloadTag) {
			tags.DeleteWorkloadTag(workloadTag)
			_, err = c.Client.UpdateProject(c.ctx, p.Uuid, p.Name, p.Version, p.Group, tags.GetAllTags())
			if err != nil {
				l.Warnf("remove tags project: %v", err)
				continue
			}
			l.Info("project tags removed")
			observability.WorkloadWithAttestation.DeleteLabelValues(workload.Namespace, workload.Name, workload.Type, strconv.FormatBool(attest), image)
		}
	}
	return err
}

func IsThisWorkload(tags *Tags, workload string) bool {
	return len(tags.WorkloadTags) == 1 && tags.WorkloadTags[0] == workload
}

func HasAttestation(p *client.Project) bool {
	return p.LastBomImportFormat != "" || p.Metrics != nil && p.Metrics.Components > 0
}

func getGroup(projectName string) string {
	groups := strings.Split(projectName, "/")
	if len(groups) > 1 {
		return groups[0]
	}
	return ""
}

func (c *Config) uploadSBOMToProject(ctx context.Context, metadata *attestation.ImageMetadata, project, parentUuid, projectVersion string) error {
	b, err := json.Marshal(metadata.Statement.Predicate)
	if err != nil {
		return err
	}

	if err = c.Client.UploadProject(ctx, project, projectVersion, parentUuid, false, b); err != nil {
		return err
	}
	return nil
}
