package monitor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
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

	if w.GetName() == "" {
		c.logger.Warnf("%s:no app name found: %s ", "delete", w.GetKind())
		return
	}

	for _, container := range w.GetContainers() {
		// check if project exists with tag
		// if only 1 wl: tag exists, delete project
		// if more than 1 wl: tag exists, remove the tag
		if err := c.deleteOrUpdateProject(w, container); err != nil {
			c.logger.Errorf("delete or update project: %v", err)
			continue
		}
	}
}

func (c *Config) OnUpdate(old any, new any) {
	c.logger.WithFields(log.Fields{"event": "update"})

	wNew := workload.GetMetadata(new, c.logger)
	wOld := workload.GetMetadata(old, c.logger)

	if wNew == nil || wOld == nil {
		return
	}

	if wNew.GetName() == "" || wOld.GetName() == "" {
		c.logger.Debugf("%s:no app name found: %s ", "update", wNew.GetKind())
		return
	}

	fmt.Println("old: " + wOld.GetIdentifier())
	fmt.Println(wOld.Active())
	fmt.Println("new: " + wNew.GetIdentifier())
	fmt.Println(wNew.Active())

	// workload is scaled up
	if wNew.Active() && !wOld.Active() {
		c.logger.Infof("scaled up %s:%s", wNew.GetKind(), wNew.GetName())
		if err := c.verifyContainers(c.ctx, wNew); err != nil {
			c.logger.Warnf("update: verify attestation: %v", err)
		}
	}

	// workload is scaled down
	if !wNew.Active() && wOld.Active() {
		c.logger.Infof("scaled down %s:%s", wNew.GetKind(), wNew.GetName())
		// check if project exists with tag
		for _, container := range wNew.GetContainers() {
			project := workload.ProjectName(wNew, c.Cluster, container.Name)
			projects, err := c.Client.GetProjectsByTag(c.ctx, toImageQuery(container.Image))
			if err != nil {
				return
			}

			if len(projects) == 0 {
				// if project does not exist or already deleted, skip
				c.logger.WithFields(log.Fields{
					"project":   project,
					"workload":  wNew.GetName(),
					"container": container.Name,
				}).Info("project does not exist, skipping")
				return
			}

			for _, p := range projects {
				// if only 1 wl: tag exists, delete project
				// if more than 1 wl: queryTag exists, remove the queryTag
				if err := c.deleteOrUpdateProject(p, wNew, project); err != nil {
					c.logger.Errorf("delete or update project: %v", err)
				}
			}
		}
	}
}

func (c *Config) deleteOrUpdateProject(project *client.Project, wNew workload.Workload, projectName string) error {
	// if only 1 wl: tag exists, delete project
	// if more than 1 wl: queryTag exists, remove the queryTag
	wlTags := findTags("wl:", project.Tags)
	if len(wlTags) == 1 {
		if !hasTag(projectName, wlTags) {
			return nil
		}

		if err := c.Client.DeleteProject(c.ctx, project.Uuid); err != nil {
			return fmt.Errorf("delete: %v", err)

		}

	} else {
		// remove wl queryTag for the workload
		var tags []string
		for _, t := range project.Tags {
			if t.Name != projectName {
				tags = append(tags, t.Name)
			}
		}
		if _, err := c.Client.UpdateProject(c.ctx, project.Uuid, project.Name, project.Version, wNew.GetNamespace(), tags); err != nil {
			return fmt.Errorf("update project: %v", err)
		}
	}
	return nil
}

func (c *Config) OnAdd(obj any) {
	c.logger.WithFields(log.Fields{"event": "add"})

	w := workload.GetMetadata(obj, c.logger)
	if w == nil {
		return
	}
	if w.GetName() == "" {
		c.logger.Debugf("%s:no app name found: %s ", "add", w.GetKind())
		return
	}
	if !w.Active() {
		c.logger.Debugf("%s:%s:%s:%s is not active, skipping", "add", w.GetKind(), w.GetName(), w.GetIdentifier())
		return
	}

	if err := c.verifyContainers(c.ctx, w); err != nil {
		c.logger.Warnf("add: verify attestation: %v", err)
	}
}

func toImageQuery(containerImage string) string {
	return url.QueryEscape("image:" + containerImage)
}

func (c *Config) verifyContainers(ctx context.Context, w workload.Workload) error {
	for _, container := range w.GetContainers() {
		project := workload.ProjectName(w, c.Cluster, container.Name)
		pp, err := c.Client.GetProjectsByTag(ctx, toImageQuery(container.Image))
		if err != nil {
			return err
		}

		var tags []string

		if len(pp) == 0 {
			metadata, err := c.verifier.Verify(c.ctx, container)
			if err != nil {
				c.logger.Warnf("verify attestation, skipping: %v", err)
				continue
			}

			projectVersion := version(container.Image)

			// create new project with new tags
			tags = []string{
				"wl:" + project,
				"namespace:" + w.GetNamespace(),
				"container:" + metadata.ContainerName,
				"image:" + metadata.Image,
				"cluster:" + c.Cluster,
				"tag:" + projectVersion,
				"digest:" + metadata.Digest,
				"rekor:" + metadata.RekorLogIndex,
			}

			createdP, err := c.Client.CreateProject(ctx, workload.ProjectName(w, "", container.Name), projectVersion, w.GetNamespace(), tags)
			if err != nil {
				return err
			}

			if err = c.uploadSBOMToProject(ctx, metadata, createdP.Name, createdP.Uuid, createdP.Version); err != nil {
				return err
			}
			log.Infof("project created and sbom uploaded: %s", project)

		} else {
			for _, p := range pp {
				wlTags := findTags("wl:", p.Tags)
				if !hasTag(project, wlTags) {
					c.logger.WithFields(log.Fields{
						"current-version": p.Version,
						"workload":        w.GetName(),
					}).Info("project exists, add tag and upload sbom")

					metadata, err := c.verifier.Verify(c.ctx, container)

					if err != nil {
						c.logger.Warnf("verify attestation, skipping: %v", err)
						continue
					}

					for _, t := range p.Tags {
						tags = append(tags, t.Name)
					}

					tags = append(tags, "wl:"+project)

					updatedProject, err := c.Client.UpdateProject(ctx, p.Uuid, p.Name, p.Version, w.GetNamespace(), tags)
					if err != nil {
						return err
					}

					if err = c.uploadSBOMToProject(ctx, metadata, updatedProject.Name, updatedProject.Uuid, updatedProject.Version); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

func findTags(substr string, tags []client.Tag) []string {
	var found []string
	for _, tag := range tags {
		if strings.Contains(tag.Name, substr) {
			found = append(found, strings.Split(tag.Name, substr)[1])
		}
	}
	return found
}

func hasTag(s string, tags []string) bool {
	fmt.Println(tags)
	fmt.Println(s)
	for _, tag := range tags {
		if tag == s {
			return true
		}
	}
	return false
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
	pr, err := c.Client.GetProjectsByTag(c.ctx, toImageQuery(container.Image))
	if err != nil {
		return fmt.Errorf("delete: get project: %v", err)
	}

	if len(pr) == 0 {
		c.logger.Debugf("%s:trying to delete project: %s, not found", w.GetKind(), container.Image)
		return nil
	}

	for _, p := range pr {
		if err = c.deleteOrUpdateProject(p, w, workload.ProjectName(w, c.Cluster, container.Name)); err != nil {
			return err
		}
	}
	return nil
}

func (c *Config) retrieveProject(ctx context.Context, projectName, env, team, app string) (*client.Project, error) {
	projects, err := c.Client.GetProjectsByTag(ctx, toImageQuery(projectName))
	if err != nil {
		return nil, fmt.Errorf("getting projects from DependencyTrack: %w", err)
	}

	if len(projects) == 0 {
		return nil, nil
	}
	var p *client.Project
	for _, project := range projects {
		if containsAllTags(project.Tags, env, team, app) && project.Classifier == "APPLICATION" {
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
