package monitor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"picante/internal/workload"

	"github.com/nais/dependencytrack/pkg/client"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/apps/v1"

	"picante/internal/attestation"
)

type Config struct {
	Client   client.Client
	Cluster  string
	verifier attestation.Verifier
	logger   *log.Entry
	ctx      context.Context
}

func NewMonitor(ctx context.Context, client client.Client, verifier attestation.Verifier, cluster string) *Config {
	return &Config{
		Client:   client,
		Cluster:  cluster,
		verifier: verifier,
		logger:   log.WithField("package", "monitor"),
		ctx:      ctx,
	}
}

func (c *Config) OnDelete(obj any) {
	//log := c.logger.WithField("event", "OnDelete")

	d := getDeployment(obj)

	project, err := c.retrieveProject(c.ctx, "instance:"+c.Cluster+"-"+d.Namespace+"-"+d.Name)
	if err != nil {
		log.Warnf("delete: retrieve project: %v", err)
		return
	}

	if project == nil {
		log.Debugf("delete: project not found")
		return
	}

	instanceTags := []string{}
	for _, tag := range project.Tags {
		if strings.Contains(tag.Name, "instance:") {
			instanceTags = append(instanceTags, tag.Name)
		}
	}

	if len(instanceTags) == 1 {
		if err = c.Client.DeleteProject(c.ctx, project.Uuid); err != nil {
			log.Warnf("delete project: %v", err)
			return
		}
	} else {
		newTags := []string{}
		for _, tag := range project.Tags {
			if tag.Name != "instance:"+c.Cluster+"-"+d.Namespace+"-"+d.Name {
				newTags = append(newTags, tag.Name)
			}
		}

		_, err = c.Client.UpdateProject(c.ctx, project.Uuid, project.Name, project.Version, project.Group, newTags)
		if err != nil {
			log.Warnf("remove tags project: %v", err)
			return
		}
	}

	/*for _, container := range d.GetContainers() {
		if err := c.deleteProject(d, container); err != nil {
			log.WithField("event", "OnDelete").Errorf("delete: %v", err)
			continue
		}
	}*/
}

func (c *Config) OnUpdate(old any, new any) {
	log := c.logger.WithField("event", "update")

	dNew := getDeployment(new)
	dOld := getDeployment(old)

	if dNew == nil || dOld == nil {
		return
	}

	if err := c.verifyDeploymentContainers(c.ctx, dNew); err != nil {
		log.Warnf("verify attestation: %v", err)
	}
}

func (c *Config) OnAdd(obj any) {
	log := c.logger.WithField("event", "add")

	deployment := getDeployment(obj)

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

/*
	func (c *Config) verifyContainers(ctx context.Context, w workload.Workload) error {
		for _, container := range w.GetContainers() {
			appName := w.GetName()
			project := workload.ProjectName(w, c.Cluster, container.Name)
			projectVersion := version(container.Image)
			pp, err := c.Client.GetProject(ctx, project, projectVersion)
			if err != nil {
				return err
			}

			// If the sbom does not exist, that's acceptable, due to it's a user error
			if pp != nil {
				c.logger.WithFields(log.Fields{
					"project":         project,
					"project-version": projectVersion,
					"workload":        w.GetName(),
					"container":       container.Name,
				}).Debug("project exist, skipping")
				continue
			} else {

				metadata, err := c.verifier.Verify(c.ctx, container)
				if err != nil {
					c.logger.Warnf("verify attestation, skipping: %v", err)
					continue
				}

				p, err := c.retrieveProject(ctx, project, c.Cluster, w.GetNamespace(), appName)
				if err != nil {
					c.logger.Warnf("retrieve project, skipping %v", err)
					continue
				}

				tags := []string{
					project,
					w.GetNamespace(),
					appName,
					metadata.ContainerName,
					metadata.Image,
					c.Cluster,
					projectVersion,
					"digest:" + metadata.Digest,
					"rekor:" + metadata.RekorLogIndex,
				}

				if p != nil {
					if !c.digestHasChanged(metadata, p) {
						c.logger.WithFields(log.Fields{
							"project-version": projectVersion,
							"workload":        w.GetName(),
							"container":       metadata.ContainerName,
							"digest":          metadata.Digest,
						}).Info("project exist and has same digest, skipping")
						continue
					}

					c.logger.WithFields(log.Fields{
						"current-version": p.Version,
						"new-version":     projectVersion,
						"workload":        w.GetName(),
						"container":       metadata.ContainerName,
						"digest":          metadata.Digest,
					}).Info("project exist update project with a new version and upload sbom...")

					_, err := c.Client.UpdateProject(ctx, p.Uuid, project, projectVersion, w.GetNamespace(), tags)
					if err != nil {
						return err
					}

					if err = c.uploadSBOMToProject(ctx, metadata, project, p.Uuid, projectVersion); err != nil {
						return err
					}

				} else {
					c.logger.WithFields(log.Fields{
						"project-version": projectVersion,
						"project":         project,
						"workload":        w.GetName(),
						"container":       metadata.ContainerName,
						"digest":          metadata.Digest,
					}).Info("project does not exist, creating...")

					createdP, err := c.Client.CreateProject(ctx, project, projectVersion, w.GetNamespace(), tags)
					if err != nil {
						return err
					}

					if err = c.uploadSBOMToProject(ctx, metadata, project, createdP.Uuid, projectVersion); err != nil {
						return err
					}
				}
			}
		}
		return nil
	}
*/
func (c *Config) verifyDeploymentContainers(ctx context.Context, d *v1.Deployment) error {
	for _, container := range d.Spec.Template.Spec.Containers {
		projectName, err := workload.ProjectNameForDeployment(d)
		if err != nil {
			return err
		}
		projectVersion := version(container.Image)
		pp, err := c.Client.GetProject(ctx, projectName, projectVersion)
		if err != nil {
			return err
		}

		// If the sbom does not exist, that's acceptable, due to it's a user error
		if pp != nil {
			c.logger.WithFields(log.Fields{
				"project":         projectName,
				"project-version": projectVersion,
				"workload":        d.GetName(),
				"container":       container.Name,
			}).Debug("project exist, skipping")

			for _, tag := range pp.Tags {
				if strings.Contains(tag.Name, "instance:") {
					if tag.Name == "instance:"+c.Cluster+"-"+d.Namespace+"-"+d.Name {
						return nil
					}
				}
			}

			tags := []string{}

			for _, tag := range pp.Tags {
				tags = append(tags, tag.Name)
			}

			tags = append(tags, "instance:"+c.Cluster+"-"+d.Namespace+"-"+d.Name)

			_, err := c.Client.UpdateProject(ctx, pp.Uuid, projectName, projectVersion, d.GetNamespace(), tags)
			if err != nil {
				return err
			}

			continue
		} else {
			metadata, err := c.verifier.Verify(c.ctx, container)
			if err != nil {
				c.logger.Warnf("verify attestation, skipping: %v", err)
				continue
			}

			p, err := c.retrieveProject(ctx, "project:"+projectName)
			if err != nil {
				c.logger.Warnf("retrieve project, skipping %v", err)
				continue
			}

			tags := []string{
				"project:" + projectName,
				"image:" + metadata.Image,
				"version" + projectVersion,
				"digest:" + metadata.Digest,
				"rekor:" + metadata.RekorLogIndex,
				"instance:" + c.Cluster + "-" + d.Namespace + "-" + d.Name,
			}

			if p != nil {
				if !c.digestHasChanged(metadata, p) {
					c.logger.WithFields(log.Fields{
						"project-version": projectVersion,
						"workload":        d.GetName(),
						"container":       metadata.ContainerName,
						"digest":          metadata.Digest,
					}).Info("project exist and has same digest, skipping")
					continue
				}

				c.logger.WithFields(log.Fields{
					"current-version": p.Version,
					"new-version":     projectVersion,
					"workload":        d.GetName(),
					"container":       metadata.ContainerName,
					"digest":          metadata.Digest,
				}).Info("project exist update project with a new version and upload sbom...")

				_, err := c.Client.UpdateProject(ctx, p.Uuid, projectName, projectVersion, d.GetNamespace(), tags)
				if err != nil {
					return err
				}

				if err = c.uploadSBOMToProject(ctx, metadata, projectName, p.Uuid, projectVersion); err != nil {
					return err
				}

			} else {
				c.logger.WithFields(log.Fields{
					"project-version": projectVersion,
					"project":         projectName,
					"workload":        d.GetName(),
					"container":       metadata.ContainerName,
					"digest":          metadata.Digest,
				}).Info("project does not exist, creating...")

				createdP, err := c.Client.CreateProject(ctx, projectName, projectVersion, d.GetNamespace(), tags)
				if err != nil {
					return err
				}

				if err = c.uploadSBOMToProject(ctx, metadata, projectName, createdP.Uuid, projectVersion); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (c *Config) digestHasChanged(metadata *attestation.ImageMetadata, p *client.Project) bool {
	for _, tag := range p.Tags {
		if strings.Contains(tag.Name, "digest:") {
			d := strings.Split(tag.Name, ":")[1]
			if d == metadata.Digest {
				return false
			}
		}
	}
	return true
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

func (c *Config) deleteProject(w workload.Workload, container workload.Container) error {
	project := workload.ProjectName(w, c.Cluster, container.Name)
	projectVersion := version(container.Image)
	pr, err := c.Client.GetProject(c.ctx, project, projectVersion)
	if err != nil {
		return fmt.Errorf("delete: get project: %v", err)
	}

	if pr == nil {
		c.logger.Debugf("%s:trying to delete project:%s:%s, project not found", w.GetKind(), project, projectVersion)
		return nil
	}

	if err = c.Client.DeleteProject(c.ctx, pr.Uuid); err != nil {
		return fmt.Errorf("delete project:%s: %v", project, err)
	}

	c.logger.Infof("%s:deleted project:%s:%s", w.GetKind(), project, projectVersion)
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

func version(image string) string {
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

func containsAllTags(tags []client.Tag, s ...string) bool {
	found := 0
	for _, t := range s {
		for _, tag := range tags {
			if tag.Name == t {
				found += 1
				break
			}
		}
	}
	return found == len(s)
}
