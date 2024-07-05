package observability

import (
	"github.com/prometheus/client_golang/prometheus"
)

var WorkloadTotalGauge = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "workload_with_sbom_total",
		Help: "Number of workloads with a sbom in a cluster namespace, type and registry.",
	},
	[]string{"cluster", "namespace", "type", "registry"},
)

var WorkloadWithAttestation = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "slsa_workload_info",
		Help: "Information about the attestation of a workload",
	},
	[]string{"workload_namespace", "workload", "workload_type", "has_attestation", "image"},
)

func init() {
	prometheus.MustRegister(WorkloadTotalGauge)
	prometheus.MustRegister(WorkloadWithAttestation)
}
