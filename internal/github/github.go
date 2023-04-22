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
	SubjectRegex string
	Repository   string
	ServerUrl    string
	Sha          string
	Workflow     string
	WorkFlowRef  string
	logger       *log.Entry
}

func NewCertificateIdentity(labels map[string]string) *CertificateIdentity {
	return &CertificateIdentity{
		SubjectRegex: "^(?:nais|navikt)\\/[a-zA-Z0-9_.-]+?\\/.github\\/workflows\\/[a-zA-Z0-9_.-]+?@refs\\/heads\\/[a-zA-Z0-9_.-]+?$",
		logger:       log.WithField("package", "github"),
		Repository:   labels[ImageRepositoryLabelKey],
		ServerUrl:    labels[ImageServerUrlLabelKey],
		Sha:          labels[ImageShaLabelKey],
		Workflow:     labels[ImageWorkflowLabelKey],
		WorkFlowRef:  labels[ImageWorkflowRefLabelKey],
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

	// nais/yolo-bolo/.github/workflows/main.yml@refs/heads/master
	re := regexp.MustCompile(c.SubjectRegex)
	if re.MatchString(c.WorkFlowRef) {
		return true
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
