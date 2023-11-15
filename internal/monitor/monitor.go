package monitor

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/nais/dependencytrack/pkg/client"
	log "github.com/sirupsen/logrus"
	"picante/internal/pod"

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
		logger:   log.WithFields(log.Fields{"package": "monitor"}),
		ctx:      ctx,
	}
}

func (c *Config) OnDelete(obj any) {
	c.logger.WithFields(log.Fields{"event": "delete"})

	p := pod.GetInfo(obj)
	if p == nil {
		c.logger.Debug("pod deleted event, but pod is nil")
		return
	}

	appName := pod.AppName(p.Labels)
	if appName == "" {
		c.logger.Debug("pod deleted event, but no app name found")
		return
	}

	for _, container := range p.ContainerImages {
		project := c.projectName(p.Namespace, appName, container.Name)
		projectVersion := version(container.Image)
		pr, err := c.Client.GetProject(c.ctx, project, projectVersion)
		if err != nil {
			c.logger.Infof("get project: %v", err)
			continue
		}

		if pr == nil {
			c.logger.Infof("trying to delete project %s, but project not found", project)
			continue
		}

		if err = c.Client.DeleteProject(c.ctx, pr.Uuid); err != nil {
			c.logger.Errorf("delete project:%s: %v", project, err)
			continue
		}

		c.logger.Infof("deleted project %s", project)
	}
}

func (c *Config) OnUpdate(old any, new any) {
	c.logger.WithFields(log.Fields{"event": "update"})
	c.logger.Debug("pod updated event, check if image needs to be attested")

	newPod := pod.GetInfo(new)
	if newPod == nil {
		c.logger.Debug("pod updated event, but pod is nil")
		return
	}

	name := pod.AppName(newPod.Labels)
	if name == "" {
		c.logger.Debug("pod updated event, but no app name found")
		return
	}

	if err := c.verifyContainers(c.ctx, newPod); err != nil {
		c.logger.Warnf("verify attestation: %v", err)
	}
}

func (c *Config) OnAdd(obj any) {
	c.logger.WithFields(log.Fields{"event": "add"})
	c.logger.Debug("new pod event, check if image needs to be attested")

	p := pod.GetInfo(obj)
	if p == nil {
		c.logger.Debug("pod added event, but pod is nil")
		return
	}

	name := pod.AppName(p.Labels)
	if name == "" {
		c.logger.Debug("pod added event, but no app name found")
		return
	}

	if err := c.verifyContainers(c.ctx, p); err != nil {
		c.logger.Warnf("verify attestation: %v", err)
	}
}

func (c *Config) verifyContainers(ctx context.Context, p *pod.Info) error {
	for _, container := range p.ContainerImages {
		appName := pod.AppName(p.Labels)
		project := c.projectName(p.Namespace, appName, container.Name)
		projectVersion := version(container.Image)
		pp, err := c.Client.GetProject(ctx, project, projectVersion)
		if err != nil {
			return err
		}

		if pp != nil && pp.LastBomImportFormat != "" {
			c.logger.WithFields(log.Fields{
				"projectVersion": projectVersion,
				"pod":            p.Name,
				"container":      container.Name,
			}).Info("project exist and has bom, skipping")
			continue
		}

		metadata, err := c.verifier.Verify(c.ctx, container)
		if err != nil {
			c.logger.Warnf("verify attestation: %v", err)
			continue
		}

		projects, err := c.Client.GetProjectsByTag(ctx, project)
		if err != nil {
			return err
		}
		tags := []string{
			project,
			p.Namespace,
			appName,
			metadata.ContainerName,
			metadata.Image,
			c.Cluster,
		}

		if len(projects) > 0 {
			c.logger.WithFields(log.Fields{
				"projectVersion": projectVersion,
				"pod":            p.Name,
				"container":      metadata.ContainerName,
			}).Info("project exist update version")

			_, err = c.Client.UpdateProject(ctx, projects[0].Uuid, project, projectVersion, p.Namespace, tags)
			if err != nil {
				return err
			}

		} else {
			c.logger.WithFields(log.Fields{
				"projectVersion": projectVersion,
				"pod":            p.Name,
				"container":      metadata.ContainerName,
			}).Info("project does not exist, creating")

			_, err = c.Client.CreateProject(ctx, project, projectVersion, p.Namespace, tags)
			if err != nil {
				return err
			}
		}

		b, err := json.Marshal(metadata.Statement.Predicate)
		if err != nil {
			return err
		}

		if err = c.Client.UploadProject(ctx, project, projectVersion, b); err != nil {
			return err
		}
	}
	return nil
}

func (c *Config) projectName(namespace, appName, containerName string) string {
	projectName := c.Cluster + ":" + namespace + ":" + appName
	if appName == containerName {
		return projectName
	}
	return projectName + ":" + containerName
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
