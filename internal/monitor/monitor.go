package monitor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"slsa-verde/internal/observability"

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

	for _, image := range workload.Images {
		projectName := getProjectName(image)
		projects, err := c.retrieveProjects(c.ctx, client.ProjectTagPrefix.With(projectName))
		if err != nil {
			l.Warnf("retrieve projects: %v", err)
			return
		}

		ll := l.WithFields(logrus.Fields{
			"project": projectName,
		})

		if err := c.cleanupWorkload(projects, workload, ll); err != nil {
			ll.Warnf("cleanup workload: %v", err)
		}
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

	if workload.Status.LastSuccessful && !pastWorkload.Status.LastSuccessful {
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
	for _, image := range workload.Images {
		var err error
		if workload.Status.ScaledDown {
			if err = c.scaledDown(ctx, workload, log); err != nil {
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

func (c *Config) scaledDown(ctx context.Context, workload *Workload, log *logrus.Entry) error {
	l := log.WithFields(logrus.Fields{
		"event":     "scale-down",
		"workload":  workload.Name,
		"namespace": workload.Namespace,
		"type":      workload.Type,
	})
	// Deployment is scaled down, we need to look for the workload tag in all found projects
	p, err := c.retrieveProjects(ctx, workload.getTag(c.Cluster))
	if err != nil {
		return err
	}

	if len(p) == 0 {
		l.Debug("no projects found for workload tag")
		return nil
	}

	if err := c.cleanupWorkload(p, workload, log); err != nil {
		return err
	}
	return nil
}

func (c *Config) verifyImage(ctx context.Context, workload *Workload, image string, log *logrus.Entry) error {
	workloadTag := workload.getTag(c.Cluster)
	projectName := getProjectName(image)
	projectVersion := getProjectVersion(image)
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
		l.Debug("project found, updating workload...")
		tags := NewTags()
		tags.ArrangeByPrefix(project.Tags)
		attest := hasAttestation(project)

		projects, err := c.retrieveProjects(ctx, client.ProjectTagPrefix.With(projectName))
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
			observability.WorkloadWithAttestation.WithLabelValues(workload.Namespace, workload.Name, workload.Type, strconv.FormatBool(attest), image).Set(1)
		} else {
			l.Debug("project already tagged with workload")
			observability.WorkloadWithAttestation.WithLabelValues(workload.Namespace, workload.Name, workload.Type, strconv.FormatBool(attest), image).Set(1)
		}
		// filter projects with the same workload tag and different version
		projects = filterProjects(projects, project)
		// cleanup projects with the same workload tag
		if err := c.cleanupWorkload(projects, workload, l); err != nil {
			return err
		}
	} else {
		metadata, err := c.verifier.Verify(c.ctx, image)
		if err != nil {
			if strings.Contains(err.Error(), attestation.ErrNoAttestation) {
				l.Debugf("skipping, %v", err)
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
		projects, err := c.retrieveProjects(ctx, client.ProjectTagPrefix.With(projectName))
		if err != nil {
			l.Warnf("retrieve project, skipping %v", err)
		}
		if err = c.cleanupWorkload(projects, workload, l); err != nil {
			return err
		}

		// if we do not find the new digest in any of projects, create a new project
		if !workloadDigestHasChanged(projects, metadata.Digest) {
			l.Info("digest has not changed, skipping")
			// TODO:verify that this is correct behaviour
			return nil
			// continue
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
		ll.Debug("project created with workload tag")
		observability.WorkloadWithAttestation.WithLabelValues(workload.Namespace, workload.Name, workload.Type, "true", image).Set(1)
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

func filterProjects(projects []*client.Project, project *client.Project) []*client.Project {
	var filteredProjects []*client.Project
	for _, p := range projects {
		if p.Version != project.Version {
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

func (c *Config) cleanupWorkload(projects []*client.Project, workload *Workload, log *logrus.Entry) error {
	var err error
	workloadTag := workload.getTag(c.Cluster)
	for _, p := range projects {
		tags := NewTags()
		tags.ArrangeByPrefix(p.Tags)
		image := tags.GetImageTag()
		attest := hasAttestation(p)

		l := log.WithFields(logrus.Fields{
			"image":           image,
			"has-attestation": attest,
		})

		if isThisWorkload(tags, workloadTag) {
			if err = c.Client.DeleteProject(c.ctx, p.Uuid); err != nil {
				l.Warnf("delete project: %v", err)
				continue
			}
			l.Debug("project deleted")
			observability.WorkloadWithAttestation.DeleteLabelValues(workload.Namespace, workload.Name, workload.Type, strconv.FormatBool(attest), image)
		} else if tags.hasWorkload(workloadTag) {
			tags.deleteWorkloadTag(workloadTag)
			_, err = c.Client.UpdateProject(c.ctx, p.Uuid, p.Name, p.Version, p.Group, tags.getAllTags())
			if err != nil {
				l.Warnf("remove tags project: %v", err)
				continue
			}
			l.Debug("project tags removed")
			observability.WorkloadWithAttestation.DeleteLabelValues(workload.Namespace, workload.Name, workload.Type, strconv.FormatBool(attest), image)
		}
	}
	return err
}

func hasAttestation(p *client.Project) bool {
	return p.LastBomImportFormat != "" || p.Metrics != nil && p.Metrics.Components > 0
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
