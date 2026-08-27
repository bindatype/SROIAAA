package broker

import "fmt"

const (
	planVersion          = 1
	fleetInventoryLimit  = 500
	monitoringIssueLimit = 25
)

type Router struct {
	liveHosts map[string]map[string]struct{}
	resources map[string]Resource
}

func NewRouter(policy Policy) (*Router, error) {
	if err := validatePolicy(policy); err != nil {
		return nil, fmt.Errorf("invalid broker policy: %w", err)
	}

	router := &Router{
		liveHosts: make(map[string]map[string]struct{}, len(policy.LiveHosts)),
		resources: make(map[string]Resource, len(policy.Resources)),
	}
	for name, resource := range policy.Resources {
		router.resources[name] = cloneResource(resource)
	}
	for host, hostPolicy := range policy.LiveHosts {
		allowed := make(map[string]struct{}, len(hostPolicy.Resources))
		for _, resource := range hostPolicy.Resources {
			allowed[resource] = struct{}{}
		}
		router.liveHosts[host] = allowed
	}
	return router, nil
}

func (r *Router) Plan(request RouteRequest) (RoutePlan, error) {
	switch request.Intent {
	case IntentFleetInventory:
		if request.Host != "" || request.Resource != "" {
			return RoutePlan{}, newRouteError("invalid_request", "fleet.inventory does not accept host or resource")
		}
		return newPlan(request.Intent, RouteStep{
			Source: SourceWazuhAPI,
			Action: "agents.list",
			Limit:  fleetInventoryLimit,
		}), nil

	case IntentAgentStatus:
		if err := requireHostOnly(request); err != nil {
			return RoutePlan{}, err
		}
		return newPlan(request.Intent, RouteStep{
			Source: SourceWazuhAPI,
			Action: "agents.status",
			Host:   request.Host,
		}), nil

	case IntentMonitoringProblems:
		if request.Resource != "" {
			return RoutePlan{}, newRouteError("invalid_request", "monitoring.problems does not accept resource")
		}
		if request.Host != "" {
			if err := validateHostSelector(request.Host); err != nil {
				return RoutePlan{}, newRouteError("invalid_host", err.Error())
			}
		}
		return newPlan(request.Intent, RouteStep{
			Source: SourceZabbixAPI,
			Action: "trigger.get",
			Host:   request.Host,
			Limit:  monitoringIssueLimit,
		}), nil

	case IntentLiveEvidence:
		return r.planLiveEvidence(request)

	default:
		return RoutePlan{}, newRouteError("unknown_intent", fmt.Sprintf("intent %q is not supported", request.Intent))
	}
}

func (r *Router) planLiveEvidence(request RouteRequest) (RoutePlan, error) {
	if request.Host == "" {
		return RoutePlan{}, newRouteError("missing_host", "live.evidence requires host")
	}
	if err := validateHostSelector(request.Host); err != nil {
		return RoutePlan{}, newRouteError("invalid_host", err.Error())
	}
	if request.Resource == "" {
		return RoutePlan{}, newRouteError("missing_resource", "live.evidence requires a resource alias")
	}
	if err := validateResourceName(request.Resource); err != nil {
		return RoutePlan{}, newRouteError("invalid_resource", err.Error())
	}

	allowedResources, ok := r.liveHosts[request.Host]
	if !ok {
		return RoutePlan{}, newRouteError("host_not_authorized", "host is not authorized for live SROIAAA access")
	}
	if _, ok := allowedResources[request.Resource]; !ok {
		return RoutePlan{}, newRouteError("resource_not_authorized", "resource is not authorized for this host")
	}
	resource := r.resources[request.Resource]

	step := RouteStep{
		Source:    SourceSROIAAA,
		Action:    "operations.execute",
		Host:      request.Host,
		Operation: resource.Operation,
		Target:    &OperationTarget{Path: resource.Path},
	}
	if resource.Params != nil {
		params := *resource.Params
		step.Params = &params
	}
	return newPlan(request.Intent, step), nil
}

func requireHostOnly(request RouteRequest) error {
	if request.Host == "" {
		return newRouteError("missing_host", fmt.Sprintf("%s requires host", request.Intent))
	}
	if request.Resource != "" {
		return newRouteError("invalid_request", fmt.Sprintf("%s does not accept resource", request.Intent))
	}
	if err := validateHostSelector(request.Host); err != nil {
		return newRouteError("invalid_host", err.Error())
	}
	return nil
}

func newPlan(intent Intent, steps ...RouteStep) RoutePlan {
	return RoutePlan{
		Version: planVersion,
		Intent:  intent,
		Steps:   steps,
	}
}

func cloneResource(resource Resource) Resource {
	clone := resource
	if resource.Params != nil {
		params := *resource.Params
		clone.Params = &params
	}
	return clone
}
