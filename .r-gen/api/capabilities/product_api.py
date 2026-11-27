"""Management APIs of self-hosted products that must not answer an anonymous caller.

Each entry names a product, the routes of its management or data API as that product's own API
documentation gives them, and what one of its answers carries (JSON keys that product's API
returns). ``request.verify`` check ``unauthenticated_api``
proves an entry: an anonymous GET of such a route answered with the product's data twice, while a
sibling route that cannot exist was not (``capabilities/request_verify.py``). Matching a route here
proves nothing by itself; it only says which answer would show the product's data.
"""
from __future__ import annotations

from dataclasses import dataclass
import re


@dataclass(frozen=True)
class ProductApi:
    product: str
    route: re.Pattern[str]
    marker: re.Pattern[str]


def _api(product: str, route: str, marker: str) -> ProductApi:
    return ProductApi(product, re.compile(route, re.I), re.compile(marker, re.S))


PRODUCT_APIS: tuple[ProductApi, ...] = (
    _api("Jupyter Server", r"^/api/(?:kernels|sessions|terminals|contents)(?:/[^/]*)?/?$",
         r'"(?:execution_state|last_activity|kernel|connections|writable|mimetype)"\s*:'),
    _api("Ray dashboard", r"^/(?:api/(?:cluster_status|jobs/?|v0/(?:nodes|actors|tasks|logs))|nodes)$",
         r'"(?:autoscaler_report|job_id|submission_id|node_id|actor_id|task_id|cluster_status|clients)"\s*:'),
    _api("MLflow tracking server", r"^/(?:ajax-)?api/2\.0/mlflow/(?:experiments|registered-models|runs|model-versions)/",
         r'"(?:experiments|experiment_id|registered_models|runs|lifecycle_stage|artifact_location)"\s*:'),
    _api("ComfyUI", r"^/(?:api/)?(?:system_stats|object_info|queue|history)$",
         r'"(?:system|devices|queue_running|queue_pending|comfyui_version|python_version|input|output_node)"\s*:'),
    _api("Ollama", r"^/api/(?:tags|ps)$", r'"models"\s*:\s*\['),
    _api("Langflow", r"^/api/v1/(?:flows/?|all|users/whoami)$",
         r'"(?:flows|is_superuser|folder_id|user_id|endpoint_name)"\s*:'),
    _api("Jenkins", r"^(?:/jenkins)?/(?:(?:asynchPeople|people|queue|computer|whoAmI)/)?api/json$",
         r'"_class"\s*:\s*"hudson\.'),
    _api("Docker Engine API", r"^(?:/v1\.[0-9]{1,2})?/(?:info|containers/json|images/json)$",
         r'"(?:Containers|ContainersRunning|KernelVersion|RepoTags|Image|ImageID)"\s*:'),
    _api("Kubelet", r"^/(?:pods|runningpods/?|configz|stats/summary|spec/?)$",
         r'"(?:kind"\s*:\s*"PodList|kubeletconfig|num_cores|machine_id|podRef)|"(?:node|pods)"\s*:\s*[\[{]'),
    _api("Kubernetes API", r"^/api/v1/(?:namespaces|secrets|pods|configmaps)/?$",
         r'"kind"\s*:\s*"(?:NamespaceList|SecretList|PodList|ConfigMapList)"'),
    _api("Container registry", r"^/v2/(?:_catalog|[a-z0-9._/-]+/tags/list)$", r'"(?:repositories|tags)"\s*:\s*\['),
    _api("Spring Boot Actuator", r"^/actuator/(?:env|configprops|mappings|beans|loggers|threaddump)$",
         r'"(?:activeProfiles|propertySources|contexts|beans|levels|threads)"\s*:'),
    _api("Jolokia", r"^/jolokia/(?:list|read|version)(?:/.*)?$", r'"(?:agent|protocol|request)"\s*:'),
    _api("Elasticsearch", r"^/(?:_cat/indices|_nodes|_cluster/(?:health|state))(?:/.*)?$",
         r'"cluster_name"\s*:|"(?:health|index|docs\.count)"\s*:'),
    _api("SCIM", r"^/scim/v2/(?:Users|Groups)/?$", r'urn:ietf:params:scim:api:messages:2\.0:ListResponse'),
    _api("WordPress REST API users", r"^/wp-json/wp/v2/users/?$", r'"slug"\s*:.*"link"\s*:'),
    _api("Grafana", r"^/api/(?:datasources|users|snapshots|org/users)$", r'"(?:isDefault|basicAuth|login|orgId)"\s*:'),
    _api("Consul", r"^/v1/(?:kv/.*|agent/self|catalog/services)$", r'"(?:Config|Member|CreateIndex|ModifyIndex)"\s*:'),
    _api("etcd", r"^/v2/keys/.*$", r'"action"\s*:\s*"get".*"node"\s*:'),
    _api("Prometheus", r"^/api/v1/(?:status/config|targets)$", r'"status"\s*:\s*"success"'),
    _api("n8n", r"^/rest/(?:workflows|credentials)$", r'"data"\s*:\s*\[.*"(?:nodes|type|name)"\s*:'),
    _api("Laravel Telescope", r"^/telescope/telescope-api/(?:requests|queries|exceptions)$", r'"entries"\s*:'),
    _api("Laravel Horizon", r"^/horizon/api/(?:stats|jobs/.*|masters)$", r'"(?:jobsPerMinute|processes|recentJobs|status)"\s*:'),
)


def product_api_for(path: str) -> ProductApi | None:
    """The product management API a route belongs to, or None."""
    route = str(path or "").split("?", 1)[0]
    return next((api for api in PRODUCT_APIS if api.route.match(route)), None)


__all__ = ["PRODUCT_APIS", "ProductApi", "product_api_for"]
