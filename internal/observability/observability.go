package observability

import (
	"github.com/prometheus/client_golang/prometheus"
)

var WorkloadWithAttestation = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "slsa_workload_info",
		Help: "Information about the attestation of a workload",
	},
	[]string{"workload_namespace", "workload", "workload_type", "has_attestation", "image"},
)

func init() {
	prometheus.MustRegister(WorkloadWithAttestation)
}
