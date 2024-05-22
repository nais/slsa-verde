package monitor

import (
	"slices"
	"strings"

	"github.com/nais/dependencytrack/pkg/client"
)

type Tags struct {
	WorkloadTags    []string
	EnvironmentTags []string
	TeamTags        []string
	OtherTags       []string
}

const (
	WorkloadTagPrefix    = "workload:"
	EnvironmentTagPrefix = "environment:"
	TeamTagPrefix        = "team:"
)

func NewTags() *Tags {
	return &Tags{}
}

func (t *Tags) ArrangeByPrefix(tags []client.Tag) {
	workloadTags := make([]string, 0)
	teamTags := make([]string, 0)
	environmentTags := make([]string, 0)
	other := make([]string, 0)

	for _, tag := range tags {
		switch {
		case strings.Contains(tag.Name, WorkloadTagPrefix):
			workloadTags = append(workloadTags, tag.Name)
		case strings.Contains(tag.Name, TeamTagPrefix):
			teamTags = append(teamTags, tag.Name)
		case strings.Contains(tag.Name, EnvironmentTagPrefix):
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
	var allTags []string
	allTags = append(allTags, t.WorkloadTags...)
	allTags = append(allTags, t.TeamTags...)
	allTags = append(allTags, t.EnvironmentTags...)
	allTags = append(allTags, t.OtherTags...)
	return allTags
}

func (t *Tags) deleteWorkloadTag(tag string) {
	var tmp []string
	for _, t := range t.WorkloadTags {
		if t != tag {
			tmp = append(tmp, t)
		}
	}
	t.WorkloadTags = tmp
	t.verifyTags()
}

func (t *Tags) verifyTags() {
	var clusterTags []string
	var envTags []string
	for _, tag := range t.WorkloadTags {
		teamTag := "team:" + getTeamFromWorkloadTag(tag)
		if !slices.Contains(clusterTags, teamTag) {
			clusterTags = append(clusterTags, teamTag)
		}
		envTag := "environment:" + getEnvironmentFromWorkloadTag(tag)
		if !slices.Contains(envTags, envTag) {
			envTags = append(envTags, envTag)
		}
	}
	t.TeamTags = clusterTags
	t.EnvironmentTags = envTags
}

func (t *Tags) addWorkloadTag(tag string) bool {
	for _, workloadTag := range t.WorkloadTags {
		if workloadTag == tag {
			return false
		}
	}
	t.WorkloadTags = append(t.WorkloadTags, tag)
	t.verifyTags()
	return true
}

func getEnvironmentFromWorkloadTag(tag string) string {
	s := strings.Split(strings.Replace(tag, WorkloadTagPrefix, "", 1), "|")
	return s[0]
}

func getTeamFromWorkloadTag(tag string) string {
	s := strings.Split(strings.Replace(tag, WorkloadTagPrefix, "", 1), "|")
	return s[1]
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