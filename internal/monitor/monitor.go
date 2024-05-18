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
	v1 "k8s.io/api/apps/v1"
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

	d := getDeployment(obj)

	if d == nil {
		log.Debugf("not a deployment")
		return
	}

	workload := workloadTag(d.GetObjectMeta(), c.Cluster, "app")
	for _, container := range d.Spec.Template.Spec.Containers {
		project, err := c.retrieveProject(c.ctx, "image:"+container.Image)
		if err != nil {
			log.Warnf("delete: retrieve project: %v", err)
			return
		}

		if project == nil {
			log.Debugf("delete: project not found")
			return
		}

		tags := NewTags()
		tags.ArrangeByPrefix(project.Tags)

		if isThisWorkload(tags, workload) {
			if err = c.Client.DeleteProject(c.ctx, project.Uuid); err != nil {
				log.Warnf("delete project: %v", err)
				return
			}
		} else {
			tags.deleteWorkloadTag(workload)
			_, err = c.Client.UpdateProject(c.ctx, project.Uuid, project.Name, project.Version, project.Group, tags.getAllTags())
			if err != nil {
				log.Warnf("remove tags project: %v", err)
				return
			}
		}
	}
}

func isThisWorkload(tags *Tags, workload string) bool {
	return len(tags.WorkloadTags) == 1 && tags.WorkloadTags[0] == workload
}

func (c *Config) OnUpdate(old any, new any) {
	log := c.logger.WithField("event", "update")

	dOld := getDeployment(old)
	dNew := getDeployment(new)

	if dNew == nil {
		return
	}

	diff := cmp.Diff(dOld.Status.Conditions, dNew.Status.Conditions)
	if diff == "" {
		return
	}

	for _, condition := range dNew.Status.Conditions {
		if condition.Type == v1.DeploymentProgressing && condition.Status == "True" && condition.Reason == "NewReplicaSetAvailable" {
			if err := c.verifyDeploymentContainers(c.ctx, dNew); err != nil {
				log.Warnf("verify attestation: %v", err)
			}
		}
	}
}

func (c *Config) OnAdd(obj any) {
	log := c.logger.WithField("event", "add")

	deployment := getDeployment(obj)

	if deployment == nil {
		log.Debugf("not a deployment")
		return
	}

	err := c.verifyDeploymentContainers(c.ctx, deployment)
	if err != nil {
		log.Warnf("add: verify attestation: %v", err)
		return
	}
}

func getDeployment(obj any) *v1.Deployment {
	if d, ok := obj.(*v1.Deployment); ok {
		return d
	}
	return nil
}

func (c *Config) verifyDeploymentContainers(ctx context.Context, d *v1.Deployment) error {
	workload := workloadTag(d.GetObjectMeta(), c.Cluster, "app")

	for _, container := range d.Spec.Template.Spec.Containers {
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
				"workload":        d.GetName(),
				"container":       container.Name,
			}).Debug("project is found, updating...")

			tags := NewTags()
			tags.ArrangeByPrefix(project.Tags)

			if tags.addWorkloadTag(workload) {
				_, err := c.Client.UpdateProject(ctx, project.Uuid, project.Name, project.Version, project.Group, tags.getAllTags())
				if err != nil {
					return err
				}
				c.logger.Debugf("project updated with workload tag:" + workload)
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

				if isThisWorkload(tags, workload) {
					if err = c.Client.DeleteProject(c.ctx, project.Uuid); err != nil {
						logrus.Warnf("delete project: %v", err)
					}
				} else {
					tags.deleteWorkloadTag(workload)
					_, err = c.Client.UpdateProject(c.ctx, project.Uuid, project.Name, project.Version, project.Group, tags.getAllTags())
					if err != nil {
						logrus.Warnf("remove tags project: %v", err)
					}
					c.logger.Debugf("project updated with workload tag:" + workload)
				}

				c.logger.WithFields(logrus.Fields{
					"project-version": projectVersion,
					"project":         projectName,
					"workload":        d.GetName(),
					"container":       metadata.ContainerName,
					"digest":          metadata.Digest,
				}).Info("project does not exist, creating...")

			}

			tags := initTags(d.GetObjectMeta(), metadata, c.Cluster, projectName, projectVersion)
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
