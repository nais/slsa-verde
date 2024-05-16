package monitor

import (
	"strings"

	"github.com/nais/dependencytrack/pkg/client"
)

type Tags struct {
	WorkloadTags    []string
	EnvironmentTags []string
	TeamTags        []string
	OtherTags       []string
}

func (t *Tags) AddTags(tags []client.Tag) {
	workloadTags := make([]string, 0)
	teamTags := make([]string, 0)
	environmentTags := make([]string, 0)
	other := make([]string, 0)

	for _, tag := range tags {
		switch {
		case strings.Contains(tag.Name, "workload:"):
			workloadTags = append(workloadTags, tag.Name)
		case strings.Contains(tag.Name, "team:"):
			teamTags = append(teamTags, tag.Name)
		case strings.Contains(tag.Name, "environment:"):
			environmentTags = append(environmentTags, tag.Name)
		default:
			other = append(other, tag.Name)
		}
	}

	t.WorkloadTags = workloadTags
	t.TeamTags = teamTags
	t.EnvironmentTags = environmentTags
	t.OtherTags = other
}

func (t *Tags) getAllTags() []string {
	allTags := []string{}
	allTags = append(allTags, t.WorkloadTags...)
	allTags = append(allTags, t.TeamTags...)
	allTags = append(allTags, t.EnvironmentTags...)
	allTags = append(allTags, t.OtherTags...)
	return allTags
}

func (t *Tags) deleteWorkloadTag(tag string) {
	tmp := []string{}
	for _, t := range t.WorkloadTags {
		if t != tag {
			tmp = append(tmp, t)
		}
	}
	t.WorkloadTags = tmp
	t.verifyTags()
}

func (t *Tags) verifyTags() {
	clusterTags := []string{}
	envTags := []string{}
	for _, tag := range t.WorkloadTags {
		clusterTags = append(clusterTags, "team:"+getTeamFromWorkloadTag(tag))
		envTags = append(envTags, "environment:"+getEnvironmentFromWorkloadTag(tag))
	}
	t.TeamTags = clusterTags
	t.EnvironmentTags = envTags
}
