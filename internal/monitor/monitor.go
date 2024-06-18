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

	workloadTag := workload.getTag(c.Cluster)
	for _, image := range workload.Images {
		projectName := getProjectName(image)
		projects, err := c.retrieveProjects(c.ctx, client.ProjectTagPrefix.With(projectName))
		if err != nil {
			l.Warnf("retrieve projects: %v", err)
			return
		}

		ll := l.WithFields(logrus.Fields{
			"project":      projectName,
			"workload-tag": workloadTag,
			"image":        image,
		})

		if err := c.cleanupWorkload(projects, workloadTag, ll); err != nil {
			ll.Warnf("cleanup workload: %v", err)
		}
	}
}

func (c *Config) OnUpdate(_ any, new any) {
	log := c.logger.WithField("event", "update")

	workload := NewWorkload(new)
	if workload == nil {
		log.Debug("not verified workload")
		return
	}

	l := log.WithFields(logrus.Fields{
		"workload":  workload.Name,
		"namespace": workload.Namespace,
		"type":      workload.Type,
	})

	if !workload.Status.LastSuccessful {
		l.Debug("workload not successful")
		return
	}

	if err := c.verifyWorkloadContainers(c.ctx, workload, l); err != nil {
		l.Warnf("verify attestation: %v", err)
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

	if !workload.Status.LastSuccessful {
		l.Debug("workload not successful")
		return
	}

	if err := c.verifyWorkloadContainers(c.ctx, workload, l); err != nil {
		l.Warnf("verify attestation: %v", err)
		return
	}
}

func (c *Config) verifyWorkloadContainers(ctx context.Context, workload *Workload, log *logrus.Entry) error {
	workloadTag := workload.getTag(c.Cluster)
	for _, image := range workload.Images {
		projectName := getProjectName(image)
		projectVersion := getProjectVersion(image)
		project, err := c.Client.GetProject(ctx, projectName, projectVersion)
		if err != nil {
			return err
		}

		l := log.WithFields(logrus.Fields{
			"project":         projectName,
			"project-version": projectVersion,
			"container":       image,
			"workload-tag":    workloadTag,
		})
		if project != nil {
			l.Debug("project found, updating workload...")
			tags := NewTags()
			tags.ArrangeByPrefix(project.Tags)

			projects, err := c.retrieveProjects(ctx, client.ProjectTagPrefix.With(project.Name))
			if err != nil {
				l.Warnf("retrieve project, skipping %v", err)
			}
			if tags.addWorkloadTag(workloadTag) {
				_, err := c.Client.UpdateProject(ctx, project.Uuid, project.Name, project.Version, project.Group, tags.getAllTags())
				if err != nil {
					return err
				}
				ll := l.WithFields(logrus.Fields{
					"project-uuid": project.Uuid,
				})
				ll.Info("project tagged with workload")
			} else {
				l.Info("project already tagged with workload")
			}
			// filter the current project from the slice of projects
			projects = filterProjects(projects, project.Version)
			// cleanup projects with the same workload tag
			if err = c.cleanupWorkload(projects, workloadTag, l); err != nil {
				return err
			}
		} else {
			metadata, err := c.verifier.Verify(c.ctx, image)
			if err != nil {
				if strings.Contains(err.Error(), attestation.ErrNoAttestation) {
					l.Debugf("skipping, %v", err)
					continue
				}
				l.Warnf("verify attestation error, skipping: %v", err)
				continue
			}

			if metadata.Statement == nil {
				l.Warn("metadata is empty, skipping")
				continue
			}

			log.WithFields(logrus.Fields{
				"digest": metadata.Digest,
			})

			l.Debug("project does not exist, updating workload ...")

			projects, err := c.retrieveProjects(ctx, client.ProjectTagPrefix.With(projectName))
			if err != nil {
				l.Warnf("retrieve project, skipping %v", err)
			}
			if err = c.cleanupWorkload(projects, workloadTag, l); err != nil {
				return err
			}

			// if we do not find the new digest in any of projects, create a new project
			if !workloadDigestHasChanged(projects, metadata.Digest) {
				l.Info("digest has not changed, skipping")
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
			ll := l.WithFields(logrus.Fields{
				"project-uuid": createdP.Uuid,
			})
			ll.Info("project created with workload tag")
		}
	}
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

func filterProjects(projects []*client.Project, version string) []*client.Project {
	var filteredProjects []*client.Project
	for _, p := range projects {
		if p.Version != version {
			filteredProjects = append(filteredProjects, p)
		}
	}
	return filteredProjects
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

func isThisWorkload(tags *Tags, workload string) bool {
	return len(tags.WorkloadTags) == 1 && tags.WorkloadTags[0] == workload
}

func (c *Config) cleanupWorkload(projects []*client.Project, workloadTag string, log *logrus.Entry) error {
	var err error
	for _, p := range projects {
		tags := NewTags()
		tags.ArrangeByPrefix(p.Tags)

		if isThisWorkload(tags, workloadTag) {
			if err = c.Client.DeleteProject(c.ctx, p.Uuid); err != nil {
				log.Warnf("delete project: %v", err)
				continue
			}
			log.Debug("project deleted with workload tag")
		} else if tags.hasWorkload(workloadTag) {
			tags.deleteWorkloadTag(workloadTag)
			_, err = c.Client.UpdateProject(c.ctx, p.Uuid, p.Name, p.Version, p.Group, tags.getAllTags())
			if err != nil {
				log.Warnf("remove tags project: %v", err)
				continue
			}
			log.Debug("project tagged with workload tag for project")
		}
	}
	return err
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
