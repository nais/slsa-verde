package github

import "github.com/sigstore/cosign/v2/pkg/cosign"

const (
	ImageRepositoryLabelKey  = "org.opencontainers.image.repository"
	ImageServerUrlLabelKey   = "org.opencontainers.image.server.url"
	ImageShaLabelKey         = "org.opencontainers.image.sha"
	ImageWorkflowLabelKey    = "org.opencontainers.image.workflow"
	ImageWorkflowRefLabelKey = "org.opencontainers.image.workflow.ref"
	IssuerUrl                = "https://token.actions.githubusercontent.com"
)

type CertificateIdentity struct {
	Repository  string
	ServerUrl   string
	Sha         string
	Workflow    string
	WorkFlowRef string
}

func NewCertificateIdentity(labels map[string]string) *CertificateIdentity {
	return &CertificateIdentity{
		Repository:  labels[ImageRepositoryLabelKey],
		ServerUrl:   labels[ImageServerUrlLabelKey],
		Sha:         labels[ImageShaLabelKey],
		Workflow:    labels[ImageWorkflowLabelKey],
		WorkFlowRef: labels[ImageWorkflowRefLabelKey],
	}
}

func (c *CertificateIdentity) Enabled() bool {
	return c.WorkFlowRef != "" && c.ServerUrl != ""
}

func (c *CertificateIdentity) GetIdentity() cosign.Identity {
	return cosign.Identity{
		Issuer:  IssuerUrl,
		Subject: c.ServerUrl + "/" + c.WorkFlowRef,
	}
}
