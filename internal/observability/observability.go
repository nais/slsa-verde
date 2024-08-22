package observability

import (
	"github.com/nais/dependencytrack/pkg/client"
	"github.com/prometheus/client_golang/prometheus"
)

var WorkloadWithAttestation = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "slsa_workload_info",
		Help: "Information about the attestation of a workload",
	},
	[]string{"workload_namespace", "workload", "workload_type", "has_attestation", "image"},
)

var WorkloadWithAttestationRiskScore = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "slsa_workload_riskscore",
		Help: "Information about the riskscore of a workload",
	},
	[]string{"workload_namespace", "workload", "workload_type", "project"},
)

var WorkloadWithAttestationCritical = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "slsa_workload_critical",
		Help: "Information about the criticality of a workload",
	},
	[]string{"workload_namespace", "workload", "workload_type", "project"},
)

func init() {
	prometheus.MustRegister(WorkloadWithAttestation)
	prometheus.MustRegister(WorkloadWithAttestationRiskScore)
	prometheus.MustRegister(WorkloadWithAttestationCritical)
}

func SetWorkloadVulnerabilityCounter(workloadNamespace, workload, workloadType, hasAttestation, image, project string, p *client.Project) {
	WorkloadWithAttestation.WithLabelValues(workloadNamespace, workload, workloadType, hasAttestation, image).Set(1)
	if p != nil && p.Metrics != nil {
		WorkloadWithAttestationRiskScore.WithLabelValues(workloadNamespace, workload, workloadType, project).Set(p.Metrics.InheritedRiskScore)
		WorkloadWithAttestationCritical.WithLabelValues(workloadNamespace, workload, workloadType, project).Set(float64(p.Metrics.Critical))
	}
}
