package monitor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"slsa-verde/internal/attestation"

	"github.com/nais/dependencytrack/pkg/client"
	"github.com/sirupsen/logrus"
)

type Config struct {
	Client   client.Client
	Cluster  string
	verifier attestation.Verifier
	logger   *logrus.Entry
	ctx      context.Context
}

func NewMonitor(ctx context.Context, client client.Client, verifier attestation.Verifier, cluster string) *Config {
	return &Config{
		Client:   client,
		Cluster:  cluster,
		verifier: verifier,
		logger:   logrus.WithField("package", "monitor"),
		ctx:      ctx,
	}
}

func getProjectName(containerImage string) string {
	if strings.Contains(containerImage, "@") {
		return strings.Split(containerImage, "@")[0]
	}
	return strings.Split(containerImage, ":")[0]
}

func (c *Config) OnDelete(obj any) {
	log := c.logger.WithField("event", "OnDelete")

	workload := NewWorkload(obj)
	if workload == nil {
		log.Debug("not a verified workload")
		return
	}

	workloadTag := workload.getTag(c.Cluster)
	for _, container := range workload.Containers {
		projectName := getProjectName(container.Image)
		projectVersion := getProjectVersion(container.Image)
		projects, err := c.retrieveProjects(c.ctx, client.ProjectTagPrefix.With(projectName))
		if err != nil {
			log.Warnf("retrieve projects: %v", err)
			return
		}

		for _, p := range projects {
			if p == nil {
				log.Debug("project not found for image: " + container.Image + "with workload tag: " + workloadTag)
				continue
			}

			tags := NewTags()
			tags.ArrangeByPrefix(p.Tags)
			log.WithFields(logrus.Fields{
				"project":  p.Name,
				"uuid":     p.Uuid,
				"workload": workloadTag,
			})

			validVersion := p.Version == projectVersion
			if isThisWorkload(tags, workloadTag) && validVersion {
				if err := c.Client.DeleteProject(c.ctx, p.Uuid); err != nil {
					c.logger.Warnf("delete project: %v", err)
					continue
				}
				c.logger.Debug("project: " + p.Uuid + " deleted with workload tag: " + workloadTag)
			} else if tags.hasWorkload(workloadTag) && validVersion {
				tags.deleteWorkloadTag(workloadTag)
				_, err := c.Client.UpdateProject(c.ctx, p.Uuid, p.Name, p.Version, p.Group, tags.getAllTags())
				if err != nil {
					c.logger.Warnf("remove tags project: %v", err)
					continue
				}
				c.logger.Debug("project with workload tag: " + workloadTag + " removed from project uuid: " + p.Uuid)
			}
		}
	}
}

func isThisWorkload(tags *Tags, workload string) bool {
	return len(tags.WorkloadTags) == 1 && tags.WorkloadTags[0] == workload
}

func (c *Config) OnUpdate(_ any, new any) {
	log := c.logger.WithField("event", "update")

	dNew := NewWorkload(new)
	if dNew == nil {
		log.Debug("not verified workload")
		return
	}

	if dNew.Status.LastSuccessful {
		if err := c.verifyWorkloadContainers(c.ctx, dNew); err != nil {
			log.Warnf("verify attestation: %v", err)
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

	if workload.Status.LastSuccessful {
		err := c.verifyWorkloadContainers(c.ctx, workload)
		if err != nil {
			log.Warnf("add: verify attestation: %v", err)
			return
		}
	}
}

func (c *Config) verifyWorkloadContainers(ctx context.Context, workload *Workload) error {
	workloadTag := workload.getTag(c.Cluster)
	for _, container := range workload.Containers {
		projectName := getProjectName(container.Image)
		projectVersion := getProjectVersion(container.Image)
		project, err := c.Client.GetProject(ctx, projectName, projectVersion)
		if err != nil {
			return err
		}

		if project != nil {
			c.logger.WithFields(logrus.Fields{
				"project":         projectName,
				"project-version": projectVersion,
				"workload":        workload.Name,
				"container":       container.Name,
			}).Info("project found, updating workload ...")

			tags := NewTags()
			tags.ArrangeByPrefix(project.Tags)

			projects, err := c.retrieveProjects(ctx, client.ProjectTagPrefix.With(project.Name))
			if err != nil {
				c.logger.Warnf("retrieve project, skipping %v", err)
			}
			if tags.addWorkloadTag(workloadTag) {
				_, err := c.Client.UpdateProject(ctx, project.Uuid, project.Name, project.Version, project.Group, tags.getAllTags())
				if err != nil {
					return err
				}
				c.logger.Info("project: " + project.Uuid + " updated with workload tag: " + workloadTag)
			} else {
				c.logger.Debug("project already has workload tag: " + workloadTag)
			}
			// filter the current project from the slice of projects
			projects = filterProjects(projects, project.Version)
			// cleanup projects with the same workload tag
			if err = c.CleanupWorkload(projects, workload, project.Version, workloadTag); err != nil {
				return err
			}
		} else {
			metadata, err := c.verifier.Verify(c.ctx, container)
			if err != nil {
				if strings.Contains(err.Error(), attestation.ErrNoAttestation) {
					c.logger.Debugf("skipping, %v", err)
					continue
				}
				c.logger.Warnf("verify attestation error, skipping: %v", err)
				continue
			}

			if metadata.Statement == nil {
				c.logger.Warn("metadata is empty, skipping")
				continue
			}

			c.logger.WithFields(logrus.Fields{
				"project-version": projectVersion,
				"project":         projectName,
				"workload":        workload.Name,
				"type":            workload.Type,
				"digest":          metadata.Digest,
			}).Info("project does not exist, updating workload ...")

			projects, err := c.retrieveProjects(ctx, client.ProjectTagPrefix.With(projectName))
			if err != nil {
				c.logger.Warnf("retrieve project, skipping %v", err)
			}
			if err = c.CleanupWorkload(projects, workload, projectVersion, workloadTag); err != nil {
				return err
			}

			// if we do not find the new digest in any of projects, create a new project
			if !workloadDigestHasChanged(projects, metadata.Digest) {
				c.logger.Debug("digest has not changed, skipping")
				continue
			}

			tags := workload.initWorkloadTags(metadata, c.Cluster, projectName, projectVersion)
			group := getGroup(projectName)
			createdP, err := c.Client.CreateProject(ctx, projectName, projectVersion, group, tags)
			if err != nil {
				return err
			}

			if err = c.uploadSBOMToProject(ctx, metadata, projectName, createdP.Uuid, projectVersion); err != nil {
				return err
			}
			c.logger.Info("project: " + createdP.Uuid + " created with workload tag: " + workloadTag)
		}
	}
	return nil
}

func workloadDigestHasChanged(projects []*client.Project, digest string) bool {
	for _, p := range projects {
		for _, tag := range p.Tags {
			if tag.Name == client.DigestTagPrefix.With(digest) {
				return false
			}
		}
	}
	return true
}

func filterProjects(projects []*client.Project, version string) []*client.Project {
	var filteredProjects []*client.Project
	for _, p := range projects {
		if p.Version != version {
			filteredProjects = append(filteredProjects, p)
		}
	}
	return filteredProjects
}

func (c *Config) CleanupWorkload(projects []*client.Project, workload *Workload, projectVersion, workloadTag string) error {
	var err error
	for _, p := range projects {
		tags := NewTags()
		tags.ArrangeByPrefix(p.Tags)

		if isThisWorkload(tags, workloadTag) {
			// TODO is this necessary?
			if workload.isJob() && p.Version == projectVersion {
				c.logger.Debug("project is a job and has the same version as the container, skipping")
				continue
			} else {
				if err := c.Client.DeleteProject(c.ctx, p.Uuid); err != nil {
					c.logger.Warnf("delete project: %v", err)
					continue
				}
				c.logger.Debug("project: " + p.Uuid + " deleted with workload tag: " + workloadTag)
			}
		} else if tags.hasWorkload(workloadTag) {
			tags.deleteWorkloadTag(workloadTag)
			_, err := c.Client.UpdateProject(c.ctx, p.Uuid, p.Name, p.Version, p.Group, tags.getAllTags())
			if err != nil {
				c.logger.Warnf("remove tags project: %v", err)
				continue
			}
			c.logger.Debug("project tagged with workload: " + workloadTag + ", removed from project uuid: " + p.Uuid)
		}
	}
	return err
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

func (c *Config) retrieveProjects(ctx context.Context, projectName string) ([]*client.Project, error) {
	tag := url.QueryEscape(projectName)
	projects, err := c.Client.GetProjectsByTag(ctx, tag)
	if err != nil {
		return nil, fmt.Errorf("getting projects from DependencyTrack: %w", err)
	}

	if len(projects) == 0 {
		return nil, nil
	}
	return projects, nil
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
