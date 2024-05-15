package monitor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/google/go-cmp/cmp"
	"github.com/nais/dependencytrack/pkg/client"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"picante/internal/attestation"
)

type CustomTags struct {
	WorkloadTags    []string
	EnvironmentTags []string
	TeamTags        []string
}

func (c *CustomTags) AddTags(tags []client.Tag) {
	workloadTags := make([]string, 0)
	teamTags := make([]string, 0)
	environmentTags := make([]string, 0)

	for _, tag := range tags {
		if strings.Contains(tag.Name, "workload:") {
			workloadTags = append(workloadTags, tag.Name)
		}
		if strings.Contains(tag.Name, "team:") {
			teamTags = append(teamTags, tag.Name)
		}
		if strings.Contains(tag.Name, "environment:") {
			environmentTags = append(environmentTags, tag.Name)
		}
	}

	c.WorkloadTags = workloadTags
	c.TeamTags = teamTags
	c.EnvironmentTags = environmentTags
}

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

func projectNameForDeployment(d *v1.Deployment) (string, error) {
	for _, container := range d.Spec.Template.Spec.Containers {
		if container.Name == d.GetName() {
			if strings.Contains(container.Image, "@") {
				return strings.Split(container.Image, "@")[0], nil
			}
			return strings.Split(container.Image, ":")[0], nil
		}
	}
	return "", fmt.Errorf("container %s not found in deployment %s", d.GetName(), d.Name)
}

func (c *Config) OnDelete(obj any) {
	log := c.logger.WithField("event", "OnDelete")

	d := getDeployment(obj)

	if d == nil {
		log.Debugf("not a deployment")
		return
	}

	project, err := c.retrieveProject(c.ctx, c.workloadTag(d.ObjectMeta, "app"))
	if err != nil {
		log.Warnf("delete: retrieve project: %v", err)
		return
	}

	if project == nil {
		log.Debugf("delete: project not found")
		return
	}

	customTags := CustomTags{}
	customTags.AddTags(project.Tags)

	if len(customTags.WorkloadTags) == 1 {
		if err = c.Client.DeleteProject(c.ctx, project.Uuid); err != nil {
			log.Warnf("delete project: %v", err)
			return
		}
	} else {
		newTags := []string{}

		deletedWorkloadTag := ""

		for _, tag := range project.Tags {
			if tag.Name != c.workloadTag(d.ObjectMeta, "app") {
				newTags = append(newTags, tag.Name)
			} else {
				deletedWorkloadTag = tag.Name
			}
		}

		newTags = verifyTags("environment:", deletedWorkloadTag, newTags)
		newTags = verifyTags("team:", deletedWorkloadTag, newTags)

		_, err = c.Client.UpdateProject(c.ctx, project.Uuid, project.Name, project.Version, project.Group, newTags)
		if err != nil {
			log.Warnf("remove tags project: %v", err)
			return
		}
	}
}

func verifyTags(tagTypePrefix, deletedWorkloadTag string, tags []string) []string {
	checkValue := ""
	switch tagTypePrefix {
	case "environment:":
		checkValue = getEnvironmentFromWorkloadTag(deletedWorkloadTag)
	case "team:":
		checkValue = getTeamFromWorkloadTag(deletedWorkloadTag)
	}

	keep := false

	for _, tag := range tags {
		if strings.HasPrefix(tag, "workload:") {
			if tagTypePrefix == "environment:" {
				if getEnvironmentFromWorkloadTag(tag) == checkValue {
					keep = true
					break
				}
			} else if tagTypePrefix == "team:" {
				if getTeamFromWorkloadTag(tag) == checkValue {
					keep = true
					break
				}
			}
		}
	}

	if !keep {
		for i, tag := range tags {
			if strings.HasPrefix(tag, tagTypePrefix) && tag == tagTypePrefix+checkValue {
				tags = append(tags[:i], tags[i+1:]...)
				break
			}
		}
	}
	return tags
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
	projectName, err := projectNameForDeployment(d)
	if err != nil {
		return err
	}

	for _, container := range d.Spec.Template.Spec.Containers {
		if !strings.Contains(container.Image, projectName) {
			continue
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
			}).Debug("project is found, updating...")

			for _, tag := range pp.Tags {
				if strings.Contains(tag.Name, "workload:") {
					if tag.Name == c.workloadTag(d.ObjectMeta, "app") {
						c.logger.Debugf("project already exists with the same workload tag, skipping...")
						return nil
					}
				}
			}

			tags := []string{}

			for _, tag := range pp.Tags {
				tags = append(tags, tag.Name)
			}

			tags = append(tags, c.workloadTag(d.ObjectMeta, "app"))

			_, err := c.Client.UpdateProject(ctx, pp.Uuid, projectName, projectVersion, d.GetNamespace(), tags)
			if err != nil {
				return err
			}
			c.logger.Debugf("project updated with workload tag:" + c.workloadTag(d.ObjectMeta, "app"))
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

			p, err := c.retrieveProject(ctx, "project:"+projectName)
			if err != nil {
				c.logger.Warnf("retrieve project, skipping %v", err)
				continue
			}

			tags := []string{
				"project:" + projectName,
				"image:" + metadata.Image,
				"version:" + projectVersion,
				"digest:" + metadata.Digest,
				"rekor:" + metadata.RekorLogIndex,
				"environment:" + c.Cluster,
				"team:" + d.GetObjectMeta().GetNamespace(),
				c.workloadTag(d.ObjectMeta, "app"),
			}

			if p != nil {
				workloadTags := []string{}
				teamTags := []string{}
				environmentTags := []string{}

				for _, tag := range p.Tags {
					if strings.Contains(tag.Name, "workload:") {
						workloadTags = append(workloadTags, tag.Name)
					}
					if strings.Contains(tag.Name, "team:") {
						teamTags = append(teamTags, tag.Name)
					}
					if strings.Contains(tag.Name, "environment:") {
						environmentTags = append(environmentTags, tag.Name)
					}
				}

				if len(workloadTags) == 1 {
					if err = c.Client.DeleteProject(c.ctx, p.Uuid); err != nil {
						log.Warnf("delete project: %v", err)
					}
					c.logger.Debugf("project deleted due last workload tag workload:" + c.workloadTag(d.ObjectMeta, "app"))
				} else {
					newTags := []string{}
					for _, tag := range p.Tags {
						if tag.Name != c.workloadTag(d.ObjectMeta, "app") {
							newTags = append(newTags, tag.Name)
						}
					}

					_, err = c.Client.UpdateProject(c.ctx, p.Uuid, p.Name, p.Version, p.Group, newTags)
					if err != nil {
						log.Warnf("remove tags project: %v", err)
					}
					c.logger.Debugf("project updated with workload tag:" + c.workloadTag(d.ObjectMeta, "app"))
				}

				c.logger.WithFields(log.Fields{
					"project-version": projectVersion,
					"project":         projectName,
					"workload":        d.GetName(),
					"container":       metadata.ContainerName,
					"digest":          metadata.Digest,
				}).Info("project does not exist, creating...")

			}
			createdP, err := c.Client.CreateProject(ctx, projectName, projectVersion, d.GetNamespace(), tags)
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

func getEnvironmentFromWorkloadTag(tag string) string {
	s := strings.Split(strings.Replace(tag, "workload:", "", 1), "|")
	return s[0]
}

func getTeamFromWorkloadTag(tag string) string {
	s := strings.Split(strings.Replace(tag, "workload:", "", 1), "|")
	return s[1]
}

func getTypeFromWorkloadTag(tag string) string {
	s := strings.Split(strings.Replace(tag, "workload:", "", 1), "|")
	return s[2]
}

func (c *Config) workloadTag(obj metav1.ObjectMeta, workloadType string) string {
	return "workload:" + c.Cluster + "|" + obj.Namespace + "|" + workloadType + "|" + obj.Name
}
