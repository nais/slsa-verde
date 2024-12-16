package orphan

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/nais/dependencytrack/pkg/client"
	nais_io_v1 "github.com/nais/liberator/pkg/apis/nais.io/v1"
	log "github.com/sirupsen/logrus"
	appsv1 "k8s.io/api/apps/v1"
	k8s "sigs.k8s.io/controller-runtime/pkg/client"
	"slsa-verde/internal/monitor"
	"slsa-verde/internal/observability"
)

type Properties struct {
	ctx       context.Context
	dpClient  client.Client
	k8sClient k8s.Client
	Cluster   string
	log       *log.Entry
}

type K8sData struct {
	WorkloadName string
	Namespace    string
}

type ProjectData struct {
	WorkloadTag string
	Project     *client.Project
}

func New(ctx context.Context, dpClient client.Client, k8sClient k8s.Client, cluster string, log *log.Entry) *Properties {
	return &Properties{
		ctx:       ctx,
		dpClient:  dpClient,
		k8sClient: k8sClient,
		Cluster:   cluster,
		log:       log,
	}
}

func (p *Properties) tidyWorkloadProject(project *client.Project, workloadTag string, dryRun bool) error {
	var err error
	tags := monitor.NewTags()
	tags.ArrangeByPrefix(project.Tags)
	image := tags.GetImageTag()
	attest := monitor.HasAttestation(project)

	l := p.log.WithFields(log.Fields{
		"image":           image,
		"has-attestation": attest,
		"workload-tag":    workloadTag,
	})

	if len(strings.Split(workloadTag, "|")) < 4 {
		l.Warn("workload tag does not contain all required fields: ", workloadTag)
		return nil
	}

	workloadName := strings.Split(workloadTag, "|")[3]
	workloadType := strings.Split(workloadTag, "|")[2]
	workloadNamespace := strings.Split(workloadTag, "|")[1]

	if monitor.IsThisWorkload(tags, workloadTag) {
		if dryRun {
			l.Infoln("Dry run: skipping project deletion:", project.Name)
			return nil
		}
		if err = p.dpClient.DeleteProject(p.ctx, project.Uuid); err != nil {
			return fmt.Errorf("error deleting project: %v", err)
		}
		l.Info("project deleted")
		observability.WorkloadWithAttestation.DeleteLabelValues(workloadNamespace, workloadName, workloadType, strconv.FormatBool(attest), image)
	} else if tags.HasWorkload(workloadTag) {
		if dryRun {
			l.Infoln("Dry run: skipping tags removal:", project.Name)
			return nil
		}
		tags.DeleteWorkloadTag(workloadTag)
		_, err = p.dpClient.UpdateProject(p.ctx, project.Uuid, project.Name, project.Version, project.Group, tags.GetAllTags())
		if err != nil {
			return fmt.Errorf("error updating project: %v", err)
		}
		l.Info("project tags removed:", project.Name)
		observability.WorkloadWithAttestation.DeleteLabelValues(workloadNamespace, workloadName, workloadType, strconv.FormatBool(attest), image)
	}
	return err
}

func (p *Properties) Run(dryRun bool) error {
	var deploymentList appsv1.DeploymentList
	err := p.k8sClient.List(p.ctx, &deploymentList)
	if err != nil {
		return fmt.Errorf("error listing deployments: %v", err)
	}

	var jobList nais_io_v1.NaisjobList
	listJobs := true
	if err = p.k8sClient.List(p.ctx, &jobList); err != nil {
		if err.Error() == "no matches for kind \"Naisjob\" in version \"nais.io/v1\"" {
			p.log.Println("Naisjob custom resource definition not found")
			listJobs = false
		} else {
			return fmt.Errorf("error listing jobs: %v", err)
		}
	}

	if listJobs {
		err = p.k8sClient.List(p.ctx, &jobList)
		if err != nil {
			return fmt.Errorf("error listing jobs: %v", err)
		}
	}

	// Create a map of workloads and their images
	k8sWorkloads := make(map[string]*K8sData) // Map workload name to image
	for _, item := range deploymentList.Items {
		k8sWorkloads[item.Name] = &K8sData{
			WorkloadName: item.GetName(),
			Namespace:    item.GetNamespace(),
		}
	}
	for _, item := range jobList.Items {
		k8sWorkloads[item.Name] = &K8sData{
			WorkloadName: item.GetName(),
			Namespace:    item.GetNamespace(),
		}
	}

	p.log.Infoln("Kubernetes workloads found:", len(k8sWorkloads))
	projectList, err := p.dpClient.GetProjectsByTag(p.ctx, client.EnvironmentTagPrefix.With(p.Cluster))
	if err != nil {
		return fmt.Errorf("error fetching projects: %v", err)
	}

	p.log.Infoln("DependencyTrack projects found:", len(projectList))
	var projectData []*ProjectData
	for _, project := range projectList {
		for _, tag := range project.Tags {
			if strings.Contains(tag.Name, client.WorkloadTagPrefix.String()+""+p.Cluster) {
				workloadName := strings.Split(tag.Name, "|")[3]
				if _, ok := k8sWorkloads[workloadName]; !ok {
					p.log.Debug("Workload not found in Kubernetes: ", workloadName)
					projectData = append(projectData, &ProjectData{
						WorkloadTag: tag.Name,
						Project:     project,
					})
				}
			}
		}
	}

	p.log.Infoln("Orphaned projects found:", len(projectData))
	for _, pd := range projectData {
		err = p.tidyWorkloadProject(pd.Project, pd.WorkloadTag, dryRun)
		if err != nil {
			return fmt.Errorf("error tidying project: %v", err)
		}
	}

	var taglog string
	var count int
	for _, project := range projectList {
		if !tagsContainsAllPrefixes(project.Tags, "rekor", "digest") {
			count++
			taglog += fmt.Sprintf("Project %s uuid %s has %d tags ||| ", project.Name, project.Uuid, len(project.Tags))
			if dryRun {
				p.log.Infoln("Dry run: skipping project deletion")
				continue
			}
			if err = p.dpClient.DeleteProject(p.ctx, project.Uuid); err != nil {
				p.log.Errorf("Error deleting project %s: %s", project.Name, err)
			}
		}
	}
	if count > 0 {
		p.log.Infoln("Projects with missing tags:", count)
		p.log.Println(taglog)
	}
	return nil
}

// find a string in a slice that contains a substring
func tagsContainsAllPrefixes(tags []client.Tag, prefixes ...string) bool {
	found := 0
	for _, prefix := range prefixes {
		for _, tag := range tags {
			if strings.Contains(tag.Name, prefix) {
				found += 1
				break
			}
		}
	}
	return found == len(prefixes)
}
