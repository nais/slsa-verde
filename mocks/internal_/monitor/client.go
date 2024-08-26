// Code generated by mockery v2.45.0. DO NOT EDIT.

package mocks

import (
	context "context"

	client "github.com/nais/dependencytrack/pkg/client"

	http "net/http"

	mock "github.com/stretchr/testify/mock"
)

// Client is an autogenerated mock type for the Client type
type Client struct {
	mock.Mock
}

// AddToTeam provides a mock function with given fields: ctx, username, uuid
func (_m *Client) AddToTeam(ctx context.Context, username string, uuid string) error {
	ret := _m.Called(ctx, username, uuid)

	if len(ret) == 0 {
		panic("no return value specified for AddToTeam")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) error); ok {
		r0 = rf(ctx, username, uuid)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ChangeAdminPassword provides a mock function with given fields: ctx, oldPassword, newPassword
func (_m *Client) ChangeAdminPassword(ctx context.Context, oldPassword string, newPassword string) error {
	ret := _m.Called(ctx, oldPassword, newPassword)

	if len(ret) == 0 {
		panic("no return value specified for ChangeAdminPassword")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) error); ok {
		r0 = rf(ctx, oldPassword, newPassword)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ConfigPropertyAggregate provides a mock function with given fields: ctx, properties
func (_m *Client) ConfigPropertyAggregate(ctx context.Context, properties []client.ConfigProperty) ([]client.ConfigProperty, error) {
	ret := _m.Called(ctx, properties)

	if len(ret) == 0 {
		panic("no return value specified for ConfigPropertyAggregate")
	}

	var r0 []client.ConfigProperty
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, []client.ConfigProperty) ([]client.ConfigProperty, error)); ok {
		return rf(ctx, properties)
	}
	if rf, ok := ret.Get(0).(func(context.Context, []client.ConfigProperty) []client.ConfigProperty); ok {
		r0 = rf(ctx, properties)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]client.ConfigProperty)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, []client.ConfigProperty) error); ok {
		r1 = rf(ctx, properties)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// CreateAdminUsers provides a mock function with given fields: ctx, users, teamUuid
func (_m *Client) CreateAdminUsers(ctx context.Context, users *client.AdminUsers, teamUuid string) error {
	ret := _m.Called(ctx, users, teamUuid)

	if len(ret) == 0 {
		panic("no return value specified for CreateAdminUsers")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *client.AdminUsers, string) error); ok {
		r0 = rf(ctx, users, teamUuid)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CreateChildProject provides a mock function with given fields: ctx, project, name, version, group, classifier, tags
func (_m *Client) CreateChildProject(ctx context.Context, project *client.Project, name string, version string, group string, classifier string, tags []string) (*client.Project, error) {
	ret := _m.Called(ctx, project, name, version, group, classifier, tags)

	if len(ret) == 0 {
		panic("no return value specified for CreateChildProject")
	}

	var r0 *client.Project
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *client.Project, string, string, string, string, []string) (*client.Project, error)); ok {
		return rf(ctx, project, name, version, group, classifier, tags)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *client.Project, string, string, string, string, []string) *client.Project); ok {
		r0 = rf(ctx, project, name, version, group, classifier, tags)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*client.Project)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *client.Project, string, string, string, string, []string) error); ok {
		r1 = rf(ctx, project, name, version, group, classifier, tags)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// CreateManagedUser provides a mock function with given fields: ctx, username, password
func (_m *Client) CreateManagedUser(ctx context.Context, username string, password string) error {
	ret := _m.Called(ctx, username, password)

	if len(ret) == 0 {
		panic("no return value specified for CreateManagedUser")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) error); ok {
		r0 = rf(ctx, username, password)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CreateOidcUser provides a mock function with given fields: ctx, email
func (_m *Client) CreateOidcUser(ctx context.Context, email string) error {
	ret := _m.Called(ctx, email)

	if len(ret) == 0 {
		panic("no return value specified for CreateOidcUser")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string) error); ok {
		r0 = rf(ctx, email)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CreateProject provides a mock function with given fields: ctx, name, version, group, tags
func (_m *Client) CreateProject(ctx context.Context, name string, version string, group string, tags []string) (*client.Project, error) {
	ret := _m.Called(ctx, name, version, group, tags)

	if len(ret) == 0 {
		panic("no return value specified for CreateProject")
	}

	var r0 *client.Project
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string, []string) (*client.Project, error)); ok {
		return rf(ctx, name, version, group, tags)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string, []string) *client.Project); ok {
		r0 = rf(ctx, name, version, group, tags)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*client.Project)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string, string, []string) error); ok {
		r1 = rf(ctx, name, version, group, tags)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// CreateTeam provides a mock function with given fields: ctx, teamName, permissions
func (_m *Client) CreateTeam(ctx context.Context, teamName string, permissions []client.Permission) (*client.Team, error) {
	ret := _m.Called(ctx, teamName, permissions)

	if len(ret) == 0 {
		panic("no return value specified for CreateTeam")
	}

	var r0 *client.Team
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, []client.Permission) (*client.Team, error)); ok {
		return rf(ctx, teamName, permissions)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, []client.Permission) *client.Team); ok {
		r0 = rf(ctx, teamName, permissions)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*client.Team)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, []client.Permission) error); ok {
		r1 = rf(ctx, teamName, permissions)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// DeleteManagedUser provides a mock function with given fields: ctx, username
func (_m *Client) DeleteManagedUser(ctx context.Context, username string) error {
	ret := _m.Called(ctx, username)

	if len(ret) == 0 {
		panic("no return value specified for DeleteManagedUser")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string) error); ok {
		r0 = rf(ctx, username)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeleteOidcUser provides a mock function with given fields: ctx, username
func (_m *Client) DeleteOidcUser(ctx context.Context, username string) error {
	ret := _m.Called(ctx, username)

	if len(ret) == 0 {
		panic("no return value specified for DeleteOidcUser")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string) error); ok {
		r0 = rf(ctx, username)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeleteProject provides a mock function with given fields: ctx, uuid
func (_m *Client) DeleteProject(ctx context.Context, uuid string) error {
	ret := _m.Called(ctx, uuid)

	if len(ret) == 0 {
		panic("no return value specified for DeleteProject")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string) error); ok {
		r0 = rf(ctx, uuid)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeleteProjects provides a mock function with given fields: ctx, name
func (_m *Client) DeleteProjects(ctx context.Context, name string) error {
	ret := _m.Called(ctx, name)

	if len(ret) == 0 {
		panic("no return value specified for DeleteProjects")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string) error); ok {
		r0 = rf(ctx, name)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeleteTeam provides a mock function with given fields: ctx, uuid
func (_m *Client) DeleteTeam(ctx context.Context, uuid string) error {
	ret := _m.Called(ctx, uuid)

	if len(ret) == 0 {
		panic("no return value specified for DeleteTeam")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string) error); ok {
		r0 = rf(ctx, uuid)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeleteUserMembership provides a mock function with given fields: ctx, uuid, username
func (_m *Client) DeleteUserMembership(ctx context.Context, uuid string, username string) error {
	ret := _m.Called(ctx, uuid, username)

	if len(ret) == 0 {
		panic("no return value specified for DeleteUserMembership")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) error); ok {
		r0 = rf(ctx, uuid, username)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// GenerateApiKey provides a mock function with given fields: ctx, uuid
func (_m *Client) GenerateApiKey(ctx context.Context, uuid string) (string, error) {
	ret := _m.Called(ctx, uuid)

	if len(ret) == 0 {
		panic("no return value specified for GenerateApiKey")
	}

	var r0 string
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (string, error)); ok {
		return rf(ctx, uuid)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) string); ok {
		r0 = rf(ctx, uuid)
	} else {
		r0 = ret.Get(0).(string)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, uuid)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetAnalysisTrail provides a mock function with given fields: ctx, projectUuid, componentUuid, vulnerabilityUuid
func (_m *Client) GetAnalysisTrail(ctx context.Context, projectUuid string, componentUuid string, vulnerabilityUuid string) (*client.Analysis, error) {
	ret := _m.Called(ctx, projectUuid, componentUuid, vulnerabilityUuid)

	if len(ret) == 0 {
		panic("no return value specified for GetAnalysisTrail")
	}

	var r0 *client.Analysis
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string) (*client.Analysis, error)); ok {
		return rf(ctx, projectUuid, componentUuid, vulnerabilityUuid)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string) *client.Analysis); ok {
		r0 = rf(ctx, projectUuid, componentUuid, vulnerabilityUuid)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*client.Analysis)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string, string) error); ok {
		r1 = rf(ctx, projectUuid, componentUuid, vulnerabilityUuid)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetConfigProperties provides a mock function with given fields: ctx
func (_m *Client) GetConfigProperties(ctx context.Context) ([]client.ConfigProperty, error) {
	ret := _m.Called(ctx)

	if len(ret) == 0 {
		panic("no return value specified for GetConfigProperties")
	}

	var r0 []client.ConfigProperty
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context) ([]client.ConfigProperty, error)); ok {
		return rf(ctx)
	}
	if rf, ok := ret.Get(0).(func(context.Context) []client.ConfigProperty); ok {
		r0 = rf(ctx)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]client.ConfigProperty)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context) error); ok {
		r1 = rf(ctx)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetCurrentProjectMetric provides a mock function with given fields: ctx, projectUuid
func (_m *Client) GetCurrentProjectMetric(ctx context.Context, projectUuid string) (*client.ProjectMetric, error) {
	ret := _m.Called(ctx, projectUuid)

	if len(ret) == 0 {
		panic("no return value specified for GetCurrentProjectMetric")
	}

	var r0 *client.ProjectMetric
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (*client.ProjectMetric, error)); ok {
		return rf(ctx, projectUuid)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) *client.ProjectMetric); ok {
		r0 = rf(ctx, projectUuid)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*client.ProjectMetric)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, projectUuid)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetEcosystems provides a mock function with given fields: ctx
func (_m *Client) GetEcosystems(ctx context.Context) ([]string, error) {
	ret := _m.Called(ctx)

	if len(ret) == 0 {
		panic("no return value specified for GetEcosystems")
	}

	var r0 []string
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context) ([]string, error)); ok {
		return rf(ctx)
	}
	if rf, ok := ret.Get(0).(func(context.Context) []string); ok {
		r0 = rf(ctx)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]string)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context) error); ok {
		r1 = rf(ctx)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetFindings provides a mock function with given fields: ctx, projectUuid, suppressed
func (_m *Client) GetFindings(ctx context.Context, projectUuid string, suppressed bool) ([]*client.Finding, error) {
	ret := _m.Called(ctx, projectUuid, suppressed)

	if len(ret) == 0 {
		panic("no return value specified for GetFindings")
	}

	var r0 []*client.Finding
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, bool) ([]*client.Finding, error)); ok {
		return rf(ctx, projectUuid, suppressed)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, bool) []*client.Finding); ok {
		r0 = rf(ctx, projectUuid, suppressed)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*client.Finding)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, bool) error); ok {
		r1 = rf(ctx, projectUuid, suppressed)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetOidcUsers provides a mock function with given fields: ctx
func (_m *Client) GetOidcUsers(ctx context.Context) ([]client.User, error) {
	ret := _m.Called(ctx)

	if len(ret) == 0 {
		panic("no return value specified for GetOidcUsers")
	}

	var r0 []client.User
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context) ([]client.User, error)); ok {
		return rf(ctx)
	}
	if rf, ok := ret.Get(0).(func(context.Context) []client.User); ok {
		r0 = rf(ctx)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]client.User)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context) error); ok {
		r1 = rf(ctx)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetProject provides a mock function with given fields: ctx, name, version
func (_m *Client) GetProject(ctx context.Context, name string, version string) (*client.Project, error) {
	ret := _m.Called(ctx, name, version)

	if len(ret) == 0 {
		panic("no return value specified for GetProject")
	}

	var r0 *client.Project
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) (*client.Project, error)); ok {
		return rf(ctx, name, version)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string) *client.Project); ok {
		r0 = rf(ctx, name, version)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*client.Project)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string) error); ok {
		r1 = rf(ctx, name, version)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetProjectById provides a mock function with given fields: ctx, uuid
func (_m *Client) GetProjectById(ctx context.Context, uuid string) (*client.Project, error) {
	ret := _m.Called(ctx, uuid)

	if len(ret) == 0 {
		panic("no return value specified for GetProjectById")
	}

	var r0 *client.Project
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (*client.Project, error)); ok {
		return rf(ctx, uuid)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) *client.Project); ok {
		r0 = rf(ctx, uuid)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*client.Project)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, uuid)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetProjectMetricsByDate provides a mock function with given fields: ctx, projectUuid, date
func (_m *Client) GetProjectMetricsByDate(ctx context.Context, projectUuid string, date string) ([]*client.ProjectMetric, error) {
	ret := _m.Called(ctx, projectUuid, date)

	if len(ret) == 0 {
		panic("no return value specified for GetProjectMetricsByDate")
	}

	var r0 []*client.ProjectMetric
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) ([]*client.ProjectMetric, error)); ok {
		return rf(ctx, projectUuid, date)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string) []*client.ProjectMetric); ok {
		r0 = rf(ctx, projectUuid, date)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*client.ProjectMetric)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string) error); ok {
		r1 = rf(ctx, projectUuid, date)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetProjects provides a mock function with given fields: ctx
func (_m *Client) GetProjects(ctx context.Context) ([]*client.Project, error) {
	ret := _m.Called(ctx)

	if len(ret) == 0 {
		panic("no return value specified for GetProjects")
	}

	var r0 []*client.Project
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context) ([]*client.Project, error)); ok {
		return rf(ctx)
	}
	if rf, ok := ret.Get(0).(func(context.Context) []*client.Project); ok {
		r0 = rf(ctx)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*client.Project)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context) error); ok {
		r1 = rf(ctx)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetProjectsByPrefixedTag provides a mock function with given fields: ctx, prefix, tag
func (_m *Client) GetProjectsByPrefixedTag(ctx context.Context, prefix client.TagPrefix, tag string) ([]*client.Project, error) {
	ret := _m.Called(ctx, prefix, tag)

	if len(ret) == 0 {
		panic("no return value specified for GetProjectsByPrefixedTag")
	}

	var r0 []*client.Project
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, client.TagPrefix, string) ([]*client.Project, error)); ok {
		return rf(ctx, prefix, tag)
	}
	if rf, ok := ret.Get(0).(func(context.Context, client.TagPrefix, string) []*client.Project); ok {
		r0 = rf(ctx, prefix, tag)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*client.Project)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, client.TagPrefix, string) error); ok {
		r1 = rf(ctx, prefix, tag)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetProjectsByTag provides a mock function with given fields: ctx, tag
func (_m *Client) GetProjectsByTag(ctx context.Context, tag string) ([]*client.Project, error) {
	ret := _m.Called(ctx, tag)

	if len(ret) == 0 {
		panic("no return value specified for GetProjectsByTag")
	}

	var r0 []*client.Project
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) ([]*client.Project, error)); ok {
		return rf(ctx, tag)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) []*client.Project); ok {
		r0 = rf(ctx, tag)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*client.Project)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, tag)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetTeam provides a mock function with given fields: ctx, team
func (_m *Client) GetTeam(ctx context.Context, team string) (*client.Team, error) {
	ret := _m.Called(ctx, team)

	if len(ret) == 0 {
		panic("no return value specified for GetTeam")
	}

	var r0 *client.Team
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (*client.Team, error)); ok {
		return rf(ctx, team)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) *client.Team); ok {
		r0 = rf(ctx, team)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*client.Team)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, team)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetTeams provides a mock function with given fields: ctx
func (_m *Client) GetTeams(ctx context.Context) ([]client.Team, error) {
	ret := _m.Called(ctx)

	if len(ret) == 0 {
		panic("no return value specified for GetTeams")
	}

	var r0 []client.Team
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context) ([]client.Team, error)); ok {
		return rf(ctx)
	}
	if rf, ok := ret.Get(0).(func(context.Context) []client.Team); ok {
		r0 = rf(ctx)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]client.Team)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context) error); ok {
		r1 = rf(ctx)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Headers provides a mock function with given fields: ctx
func (_m *Client) Headers(ctx context.Context) (http.Header, error) {
	ret := _m.Called(ctx)

	if len(ret) == 0 {
		panic("no return value specified for Headers")
	}

	var r0 http.Header
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context) (http.Header, error)); ok {
		return rf(ctx)
	}
	if rf, ok := ret.Get(0).(func(context.Context) http.Header); ok {
		r0 = rf(ctx)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(http.Header)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context) error); ok {
		r1 = rf(ctx)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// PortfolioRefresh provides a mock function with given fields: ctx
func (_m *Client) PortfolioRefresh(ctx context.Context) error {
	ret := _m.Called(ctx)

	if len(ret) == 0 {
		panic("no return value specified for PortfolioRefresh")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context) error); ok {
		r0 = rf(ctx)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RecordAnalysis provides a mock function with given fields: ctx, analysis
func (_m *Client) RecordAnalysis(ctx context.Context, analysis *client.AnalysisRequest) error {
	ret := _m.Called(ctx, analysis)

	if len(ret) == 0 {
		panic("no return value specified for RecordAnalysis")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *client.AnalysisRequest) error); ok {
		r0 = rf(ctx, analysis)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RemoveAdminUsers provides a mock function with given fields: ctx, users
func (_m *Client) RemoveAdminUsers(ctx context.Context, users *client.AdminUsers) error {
	ret := _m.Called(ctx, users)

	if len(ret) == 0 {
		panic("no return value specified for RemoveAdminUsers")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *client.AdminUsers) error); ok {
		r0 = rf(ctx, users)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// TriggerAnalysis provides a mock function with given fields: ctx, projectUuid
func (_m *Client) TriggerAnalysis(ctx context.Context, projectUuid string) error {
	ret := _m.Called(ctx, projectUuid)

	if len(ret) == 0 {
		panic("no return value specified for TriggerAnalysis")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string) error); ok {
		r0 = rf(ctx, projectUuid)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// UpdateProject provides a mock function with given fields: ctx, uuid, name, version, group, tags
func (_m *Client) UpdateProject(ctx context.Context, uuid string, name string, version string, group string, tags []string) (*client.Project, error) {
	ret := _m.Called(ctx, uuid, name, version, group, tags)

	if len(ret) == 0 {
		panic("no return value specified for UpdateProject")
	}

	var r0 *client.Project
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string, string, []string) (*client.Project, error)); ok {
		return rf(ctx, uuid, name, version, group, tags)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string, string, []string) *client.Project); ok {
		r0 = rf(ctx, uuid, name, version, group, tags)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*client.Project)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string, string, string, []string) error); ok {
		r1 = rf(ctx, uuid, name, version, group, tags)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// UpdateProjectInfo provides a mock function with given fields: ctx, uuid, version, group, tags
func (_m *Client) UpdateProjectInfo(ctx context.Context, uuid string, version string, group string, tags []string) error {
	ret := _m.Called(ctx, uuid, version, group, tags)

	if len(ret) == 0 {
		panic("no return value specified for UpdateProjectInfo")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string, []string) error); ok {
		r0 = rf(ctx, uuid, version, group, tags)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// UploadProject provides a mock function with given fields: ctx, name, version, parentUuid, autoCreate, bom
func (_m *Client) UploadProject(ctx context.Context, name string, version string, parentUuid string, autoCreate bool, bom []byte) error {
	ret := _m.Called(ctx, name, version, parentUuid, autoCreate, bom)

	if len(ret) == 0 {
		panic("no return value specified for UploadProject")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string, bool, []byte) error); ok {
		r0 = rf(ctx, name, version, parentUuid, autoCreate, bom)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Version provides a mock function with given fields: ctx
func (_m *Client) Version(ctx context.Context) (string, error) {
	ret := _m.Called(ctx)

	if len(ret) == 0 {
		panic("no return value specified for Version")
	}

	var r0 string
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context) (string, error)); ok {
		return rf(ctx)
	}
	if rf, ok := ret.Get(0).(func(context.Context) string); ok {
		r0 = rf(ctx)
	} else {
		r0 = ret.Get(0).(string)
	}

	if rf, ok := ret.Get(1).(func(context.Context) error); ok {
		r1 = rf(ctx)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// NewClient creates a new instance of Client. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewClient(t interface {
	mock.TestingT
	Cleanup(func())
}) *Client {
	mock := &Client{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
