package broker

type Intent string

const (
	IntentFleetInventory     Intent = "fleet.inventory"
	IntentAgentStatus        Intent = "agent.status"
	IntentMonitoringProblems Intent = "monitoring.problems"
	IntentLiveEvidence       Intent = "live.evidence"
	IntentDatabaseQuery      Intent = "database.query"
)

type Source string

const (
	SourceWazuhAPI  Source = "wazuh-api"
	SourceZabbixAPI Source = "zabbix-api"
	SourceSROIAAA   Source = "sroiaaa-agent"
	SourcePegasusDB Source = "pegasus-db"
)

// SourceForIntent reports which data source an intent routes to. It lets a
// caller discover, before planning, whether an intent is executable at all --
// so a model is never offered an intent whose connector does not exist.
func SourceForIntent(intent Intent) (Source, bool) {
	switch intent {
	case IntentFleetInventory, IntentAgentStatus:
		return SourceWazuhAPI, true
	case IntentMonitoringProblems:
		return SourceZabbixAPI, true
	case IntentLiveEvidence:
		return SourceSROIAAA, true
	case IntentDatabaseQuery:
		return SourcePegasusDB, true
	default:
		return "", false
	}
}

// AllIntents lists every intent the router can plan.
func AllIntents() []Intent {
	return []Intent{
		IntentFleetInventory,
		IntentAgentStatus,
		IntentMonitoringProblems,
		IntentLiveEvidence,
		IntentDatabaseQuery,
	}
}

type RouteRequest struct {
	Intent   Intent `json:"intent"`
	Host     string `json:"host,omitempty"`
	Resource string `json:"resource,omitempty"`
	// Query is the one field a model may author rather than choose from a
	// fixed set. It applies to database.query only, where the credential's
	// single-schema read grant bounds the damage class in a way that no
	// filesystem path could.
	Query string `json:"query,omitempty"`
}

type RoutePlan struct {
	Version int         `json:"version"`
	Intent  Intent      `json:"intent"`
	Steps   []RouteStep `json:"steps"`
}

type RouteStep struct {
	Source    Source           `json:"source"`
	Action    string           `json:"action"`
	Host      string           `json:"host,omitempty"`
	Limit     int              `json:"limit,omitempty"`
	Operation string           `json:"operation,omitempty"`
	Query     string           `json:"query,omitempty"`
	Target    *OperationTarget `json:"target,omitempty"`
	Params    *OperationParams `json:"params,omitempty"`
}

type OperationTarget struct {
	Path string `json:"path"`
}

type OperationParams struct {
	Offset     int64 `json:"offset,omitempty"`
	MaxBytes   int64 `json:"max_bytes,omitempty"`
	MaxEntries int   `json:"max_entries,omitempty"`
}

type Policy struct {
	Version   int                   `json:"version"`
	LiveHosts map[string]HostPolicy `json:"live_hosts"`
	Resources map[string]Resource   `json:"resources"`
}

type HostPolicy struct {
	Resources []string `json:"resources"`
}

type Resource struct {
	Operation string           `json:"operation"`
	Path      string           `json:"path"`
	Params    *OperationParams `json:"params,omitempty"`
}

type RouteError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *RouteError) Error() string {
	return e.Code + ": " + e.Message
}

func newRouteError(code, message string) *RouteError {
	return &RouteError{Code: code, Message: message}
}
