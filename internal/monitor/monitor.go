package monitor

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/nais/dependencytrack/pkg/client"
	log "github.com/sirupsen/logrus"
	"picante/internal/workload"

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
	c.logger.WithFields(log.Fields{"event": "OnDelete"})

	w := workload.GetMetadata(obj, c.logger)
	if w == nil {
		return
	}

	if !c.validWorkload("delete", w) {
		return
	}

	for _, container := range w.GetContainers() {
		project := workload.ProjectName(w, c.Cluster, container.Name)
		projectVersion := version(container.Image)
		pr, err := c.Client.GetProject(c.ctx, project, projectVersion)
		if err != nil {
			c.logger.Infof("get project: %v", err)
			continue
		}

		if pr == nil {
			c.logger.Infof("trying to delete project %s, project not found", project)
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

	w := workload.GetMetadata(new, c.logger)
	if w == nil {
		return
	}

	if !c.validWorkload("update", w) {
		return
	}

	if err := c.verifyContainers(c.ctx, w); err != nil {
		c.logger.Warnf("verify attestation: %v", err)
	}
}

func (c *Config) OnAdd(obj any) {
	c.logger.WithFields(log.Fields{"event": "add"})

	w := workload.GetMetadata(obj, c.logger)
	if w == nil {
		return
	}

	if !c.validWorkload("add", w) {
		return
	}

	if err := c.verifyContainers(c.ctx, w); err != nil {
		c.logger.Warnf("verify attestation: %v", err)
	}
}

func (c *Config) verifyContainers(ctx context.Context, w workload.Workload) error {
	for _, container := range w.GetContainers() {
		appName := w.GetName()
		project := workload.ProjectName(w, c.Cluster, container.Name)
		projectVersion := version(container.Image)
		pp, err := c.Client.GetProject(ctx, project, projectVersion)
		if err != nil {
			return err
		}

		if pp != nil && pp.LastBomImportFormat != "" {
			c.logger.WithFields(log.Fields{
				"project":        project,
				"projectVersion": projectVersion,
				"workload":       w.GetName(),
				"container":      container.Name,
			}).Debug("project exist and has bom, skipping")
		} else {

			projects, err := c.Client.GetProjectsByTag(ctx, project)
			if err != nil {
				return err
			}

			metadata, err := c.verifier.Verify(c.ctx, container)
			if err != nil {
				c.logger.Warnf("verify attestation: %v", err)
				continue
			}

			tags := []string{
				project,
				w.GetNamespace(),
				appName,
				metadata.ContainerName,
				metadata.Image,
				c.Cluster,
			}

			if len(projects) > 0 {
				c.logger.WithFields(log.Fields{
					"projectVersion": projectVersion,
					"workload":       w.GetName(),
					"container":      metadata.ContainerName,
				}).Info("project exist update version")

				_, err = c.Client.UpdateProject(ctx, projects[0].Uuid, project, projectVersion, w.GetNamespace(), tags)
				if err != nil {
					return err
				}

			} else {
				c.logger.WithFields(log.Fields{
					"projectVersion": projectVersion,
					"workload":       w.GetName(),
					"container":      metadata.ContainerName,
				}).Info("project does not exist, creating")

				_, err = c.Client.CreateProject(ctx, project, projectVersion, w.GetNamespace(), tags)
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
	}
	return nil
}

func (c *Config) validWorkload(event string, w workload.Workload) bool {
	if w == nil {
		return false
	}
	if w.GetName() == "" {
		c.logger.Warnf("%s event, no app name found: %s ", event, w.GetKind())
		return false
	}
	if !w.Active() {
		c.logger.Debugf("%s event, %s:%s:%s is not active, skipping", event, w.GetKind(), w.GetName(), w.GetIdentifier())
		return false
	}
	return true
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
