package github

import (
	"github.com/sigstore/cosign/v2/pkg/cosign"
	log "github.com/sirupsen/logrus"
	"regexp"
)

const (
	ImageRepositoryLabelKey  = "org.opencontainers.image.repository"
	ImageServerUrlLabelKey   = "org.opencontainers.image.server.url"
	ImageShaLabelKey         = "org.opencontainers.image.sha"
	ImageWorkflowLabelKey    = "org.opencontainers.image.workflow"
	ImageWorkflowRefLabelKey = "org.opencontainers.image.workflow.ref"
	IssuerUrl                = "https://token.actions.githubusercontent.com"
	DefaultServerUrl         = "https://github.com"
)

type CertificateIdentity struct {
	logger        *log.Entry
	Organizations []string
	Repository    string
	ServerUrl     string
	Sha           string
	Workflow      string
	WorkFlowRef   string
}

func NewCertificateIdentity(organisations []string, labels map[string]string) *CertificateIdentity {
	return &CertificateIdentity{
		logger:        log.WithField("package", "github"),
		Organizations: organisations,
		Repository:    labels[ImageRepositoryLabelKey],
		ServerUrl:     labels[ImageServerUrlLabelKey],
		Sha:           labels[ImageShaLabelKey],
		Workflow:      labels[ImageWorkflowLabelKey],
		WorkFlowRef:   labels[ImageWorkflowRefLabelKey],
	}
}

func (c *CertificateIdentity) Enabled() bool {
	return c.WorkFlowRef != "" && c.ServerUrl != ""
}

func (c *CertificateIdentity) IsValid() bool {
	if c.ServerUrl != DefaultServerUrl {
		c.logger.WithFields(log.Fields{
			"serverUrl": c.ServerUrl,
		}).Warnf("server_url does not match default server url")
		return false
	}

	for _, org := range c.Organizations {
		// nais/yolo-bolo/.github/workflows/main.yml@refs/heads/master
		re := regexp.MustCompile("^" + org + "\\/[a-zA-Z0-9_.-]+?\\/.github\\/workflows\\/[a-zA-Z0-9_-]+?(?:.yaml|.yml)@refs\\/heads\\/[a-zA-Z0-9_-]+?$")
		if re.MatchString(c.WorkFlowRef) {
			return true
		}
	}
	c.logger.WithFields(log.Fields{
		"workFlowRef": c.WorkFlowRef,
	}).Warnf("workFlowRef does not match pattern")
	return false
}

func (c *CertificateIdentity) GetIdentity() cosign.Identity {
	return cosign.Identity{
		Issuer:  IssuerUrl,
		Subject: c.ServerUrl + "/" + c.WorkFlowRef,
	}
}
