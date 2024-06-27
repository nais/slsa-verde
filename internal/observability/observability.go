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

func init() {
	prometheus.MustRegister(WorkloadTotalGauge)
}
