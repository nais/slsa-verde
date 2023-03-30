package pod

type LabelType string

const (
	LabelTypeAppK8sIoName          LabelType = "app.kubernetes.io/name"
	LabelTypeSalsaKeyRefLabel      LabelType = "nais.io/salsa-key-ref"
	LabelTypeSalsaKeylessProvider  LabelType = "nais.io/salsa-keyless-provider"
	LabelTypeSalsaPredicateLabel   LabelType = "nais.io/salsa-predicate"
	LabelTypeTeamLabel             LabelType = "team"
	LabelTypeIgnoreTransparencyLog LabelType = "nais.io/salsa-ignore-transparency-log"
)

func (l LabelType) String() string {
	return string(l)
}
