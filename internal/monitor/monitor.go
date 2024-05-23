package monitor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"picante/internal/attestation"

	"github.com/google/go-cmp/cmp"
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
		log.Debugf("not a verified workload")
		return
	}

	workloadTag := workload.getTag(c.Cluster)
	for _, container := range workload.Containers {
		project, err := c.retrieveProject(c.ctx, "image:"+container.Image)
		if err != nil {
			log.Warnf("delete: retrieve project: %v", err)
			return
		}

		if project == nil {
			log.Debugf("delete: project not found for image: " + container.Image + "with workload tag: " + workloadTag)
			return
		}

		tags := NewTags()
		tags.ArrangeByPrefix(project.Tags)

		if isThisWorkload(tags, workloadTag) {
			if err = c.Client.DeleteProject(c.ctx, project.Uuid); err != nil {
				log.Warnf("delete project: %v", err)
				return
			}
			log.Debugf("project deleted with workload tag: " + workloadTag)
		} else {
			tags.deleteWorkloadTag(workloadTag)
			_, err = c.Client.UpdateProject(c.ctx, project.Uuid, project.Name, project.Version, project.Group, tags.getAllTags())
			if err != nil {
				log.Warnf("remove tags project: %v", err)
				return
			}
			log.Debugf("project with workload tag: " + workloadTag + " removed")
		}
	}
}

func isThisWorkload(tags *Tags, workload string) bool {
	return len(tags.WorkloadTags) == 1 && tags.WorkloadTags[0] == workload
}

func (c *Config) OnUpdate(old any, new any) {
	log := c.logger.WithField("event", "update")

	dOld := NewWorkload(old)
	dNew := NewWorkload(new)
	if dNew == nil {
		log.Debugf("not verified workload")
		return
	}

	diff := cmp.Diff(dOld.Status, dNew.Status)
	if diff == "" {
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
		log.Debugf("not a verified workload")
		return
	}

	err := c.verifyWorkloadContainers(c.ctx, workload)
	if err != nil {
		log.Warnf("add: verify attestation: %v", err)
		return
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
			}).Debug("project is found, updating...")

			tags := NewTags()
			tags.ArrangeByPrefix(project.Tags)
			if tags.addWorkloadTag(workloadTag) {
				_, err := c.Client.UpdateProject(ctx, project.Uuid, project.Name, project.Version, project.Group, tags.getAllTags())
				if err != nil {
					return err
				}
				c.logger.Debugf("project updated with workload tag: " + workloadTag)
				continue
			}

			c.logger.Debugf("project already has workload tag")
			continue
		} else {
			metadata, err := c.verifier.Verify(c.ctx, container)
			if err != nil {
				c.logger.Warnf("verify attestation, skipping: %v", err)
				continue
			}

			if metadata.Statement == nil {
				c.logger.Warnf("metadata is empty, skipping")
				continue
			}

			project, err := c.retrieveProject(ctx, "project:"+projectName)
			if err != nil {
				c.logger.Warnf("retrieve project, skipping %v", err)
				continue
			}

			if project != nil {
				tags := NewTags()
				tags.ArrangeByPrefix(project.Tags)

				if isThisWorkload(tags, workloadTag) {
					if err = c.Client.DeleteProject(c.ctx, project.Uuid); err != nil {
						logrus.Warnf("delete project: %v", err)
					}
					c.logger.Debugf("project deleted with workload tag: " + workloadTag)
				} else {
					tags.deleteWorkloadTag(workloadTag)
					_, err = c.Client.UpdateProject(c.ctx, project.Uuid, project.Name, project.Version, project.Group, tags.getAllTags())
					if err != nil {
						logrus.Warnf("remove tags project: %v", err)
					}
					c.logger.Debugf("project with workload tag: " + workloadTag + " removed")
				}

				c.logger.WithFields(logrus.Fields{
					"project-version": projectVersion,
					"project":         projectName,
					"workload":        workload.Name,
					"container":       metadata.ContainerName,
					"digest":          metadata.Digest,
				}).Info("project does not exist, creating...")

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
		}
	}
	return nil
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

func (c *Config) retrieveProject(ctx context.Context, projectName string) (*client.Project, error) {
	tag := url.QueryEscape(projectName)
	projects, err := c.Client.GetProjectsByTag(ctx, tag)
	if err != nil {
		return nil, fmt.Errorf("getting projects from DependencyTrack: %w", err)
	}

	if len(projects) == 0 {
		return nil, nil
	}
	var p *client.Project
	for _, project := range projects {
		if containsAllTags(project.Tags, projectName) && project.Classifier == "APPLICATION" {
			p = project
			break
		}
	}
	return p, nil
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
