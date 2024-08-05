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
		case strings.Contains(tag.Name, client.WorkloadTagPrefix.String()):
			workloadTags = append(workloadTags, tag.Name)
		case strings.Contains(tag.Name, client.TeamTagPrefix.String()):
			teamTags = append(teamTags, tag.Name)
		case strings.Contains(tag.Name, client.EnvironmentTagPrefix.String()):
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
	for _, tt := range t.WorkloadTags {
		if tt != tag {
			tmp = append(tmp, tt)
		}
	}
	t.WorkloadTags = tmp
	t.verifyTags()
}

func (t *Tags) verifyTags() {
	var clusterTags []string
	var envTags []string
	for _, tag := range t.WorkloadTags {
		teamTag := client.TeamTagPrefix.With(getTeamFromWorkloadTag(tag))
		if !slices.Contains(clusterTags, teamTag) {
			clusterTags = append(clusterTags, teamTag)
		}
		envTag := client.EnvironmentTagPrefix.With(getEnvironmentFromWorkloadTag(tag))
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

func (t *Tags) hasWorkload(tag string) bool {
	for _, workloadTag := range t.WorkloadTags {
		if workloadTag == tag {
			return true
		}
	}
	return false
}

func getEnvironmentFromWorkloadTag(tag string) string {
	s := strings.Split(strings.Replace(tag, client.WorkloadTagPrefix.String(), "", 1), "|")
	return s[0]
}

func getTeamFromWorkloadTag(tag string) string {
	s := strings.Split(strings.Replace(tag, client.WorkloadTagPrefix.String(), "", 1), "|")
	return s[1]
}

func getTypeFromWorkloadTag(tag string) string {
	s := strings.Split(strings.Replace(tag, client.WorkloadTagPrefix.String(), "", 1), "|")
	return s[2]
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
