"""Management APIs of self-hosted products that must not answer an anonymous caller.

Each entry names a product, the routes of its management or data API as that product's own API
documentation gives them, and what one of its answers carries: JSON keys only that product's API
returns together (never one key any JSON API has). ``request.verify`` check ``unauthenticated_api``
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
    # Every one must be found in the answer. One key (``"status": "success"``, ``"models": [``,
    # ``"login":``) is what any JSON API answers; a product is told by keys it alone returns
    # *together*, so each entry names a conjunction.
    markers: tuple[re.Pattern[str], ...]

    def answers(self, text: str) -> bool:
        """Whether ``text`` (a response body) carries every marker of this product's answer.

        The patterns run on target-controlled text, so each is one literal key with at most one
        whitespace quantifier, searched on its own: no ``.*`` joins two of them.
        """
        return all(marker.search(text) for marker in self.markers)


def _key(name: str, value: str = "") -> str:
    """A JSON object key (``"name":``), optionally with the start of its value."""
    return f'"{re.escape(name)}"\\s*:' + (f"\\s*{value}" if value else "")


def _api(product: str, route: str, *keys: str) -> ProductApi:
    """An entry whose answer must carry every key in ``keys``. A key is a JSON key name, or
    ``name=<value regex>`` when the value is part of what tells the product."""
    if len(keys) < 2 and "=" not in "".join(keys):
        raise ValueError(f"{product}: an answer is told by two keys together, or by a key with its value")
    markers = tuple(re.compile(_key(*key.split("=", 1))) for key in keys)
    return ProductApi(product, re.compile(route, re.I), markers)


# Routes and keys are each product's documented answer for that route. Left out on purpose: a
# route that answers an anonymous caller by design (Jenkins /whoAmI), one read with POST (Laravel
# Telescope's entry lists: this check sends GET), and one whose answer has no keys of its own
# (Jupyter terminals, ComfyUI /history, Consul catalog/services, Horizon job lists, n8n
# credentials): a generic application at the same path would answer the same.
PRODUCT_APIS: tuple[ProductApi, ...] = (
    _api("Jupyter Server", r"^/api/(?:kernels|sessions)(?:/[^/]*)?/?$", "execution_state", "connections"),
    _api("Jupyter Server", r"^/api/contents(?:/[^/]*)?/?$", "writable", "mimetype", "last_modified"),
    _api("Ray dashboard", r"^/api/cluster_status$", "autoscalingStatus", "clusterStatus"),
    _api("Ray dashboard", r"^/api/jobs/?$", "submission_id", "entrypoint"),
    _api("Ray dashboard", r"^/api/v0/nodes$", "node_id", "is_head_node"),
    _api("Ray dashboard", r"^/api/v0/actors$", "actor_id", "class_name"),
    _api("Ray dashboard", r"^/api/v0/tasks$", "task_id", "func_or_class_name"),
    _api("Ray dashboard", r"^/nodes$", "result", "raylet"),
    _api("MLflow tracking server", r"^/(?:ajax-)?api/2\.0/mlflow/experiments/",
         "experiment_id", "artifact_location", "lifecycle_stage"),
    _api("MLflow tracking server", r"^/(?:ajax-)?api/2\.0/mlflow/registered-models/",
         "registered_models", "creation_timestamp"),
    _api("MLflow tracking server", r"^/(?:ajax-)?api/2\.0/mlflow/runs/", "run_id", "artifact_uri", "lifecycle_stage"),
    _api("MLflow tracking server", r"^/(?:ajax-)?api/2\.0/mlflow/model-versions/", "model_versions", "current_stage"),
    _api("ComfyUI", r"^/(?:api/)?system_stats$", "devices", "vram_total", "python_version"),
    _api("ComfyUI", r"^/(?:api/)?object_info$", "output_node", "output_is_list", "display_name"),
    _api("ComfyUI", r"^/(?:api/)?queue$", "queue_running", "queue_pending"),
    _api("Ollama", r"^/api/tags$", r"models=\[", "digest", "modified_at"),
    _api("Ollama", r"^/api/ps$", r"models=\[", "digest", "size_vram"),
    _api("Langflow", r"^/api/v1/flows/?$", "is_component", "user_id"),
    _api("Langflow", r"^/api/v1/all$", "base_classes", "display_name", "template"),
    _api("Langflow", r"^/api/v1/users/whoami$", "is_superuser", "create_at"),
    _api("Jenkins", r"^(?:/jenkins)?/(?:(?:asynchPeople|people|queue|computer)/)?api/json$",
         r'_class="hudson\.'),
    _api("Docker Engine API", r"^(?:/v1\.[0-9]{1,2})?/info$", "KernelVersion", "DockerRootDir", "ContainersRunning"),
    _api("Docker Engine API", r"^(?:/v1\.[0-9]{1,2})?/containers/json$", "ImageID", "Names", "Command"),
    _api("Docker Engine API", r"^(?:/v1\.[0-9]{1,2})?/images/json$", "RepoTags", "ParentId"),
    _api("Kubelet", r"^/(?:pods|runningpods/?)$", r'kind="PodList"', "apiVersion"),
    _api("Kubelet", r"^/configz$", "kubeletconfig", "syncFrequency"),
    _api("Kubelet", r"^/stats/summary$", "nodeName", "usageNanoCores"),
    _api("Kubelet", r"^/spec/?$", "num_cores", "machine_id", "boot_id"),
    _api("Kubernetes API", r"^/api/v1/(?:namespaces|secrets|pods|configmaps)/?$",
         r'kind="(?:NamespaceList|SecretList|PodList|ConfigMapList)"', "apiVersion"),
    _api("Container registry", r"^/v2/_catalog$", r"repositories=\["),
    _api("Container registry", r"^/v2/[a-z0-9._/-]+/tags/list$", r"tags=\[", "name"),
    _api("Spring Boot Actuator", r"^/actuator/env$", "activeProfiles", "propertySources"),
    _api("Spring Boot Actuator", r"^/actuator/configprops$", "contexts", "beans", "prefix"),
    _api("Spring Boot Actuator", r"^/actuator/mappings$", "contexts", "mappings", "predicate", "handler"),
    _api("Spring Boot Actuator", r"^/actuator/beans$", "contexts", "beans", "dependencies"),
    _api("Spring Boot Actuator", r"^/actuator/loggers$", "levels", "effectiveLevel"),
    _api("Spring Boot Actuator", r"^/actuator/threaddump$", "threads", "threadName", "threadState"),
    _api("Jolokia", r"^/jolokia/version/?$", "agent", "protocol", "timestamp"),
    _api("Jolokia", r"^/jolokia/list(?:/[^?]*)?$", r'type="list"', "request", "timestamp", "status=200"),
    _api("Jolokia", r"^/jolokia/read(?:/[^?]*)?$", r'type="read"', "mbean", "timestamp", "status=200"),
    _api("Elasticsearch", r"^/_cat/indices(?:/[^?]*)?$", "docs.count", "pri.store.size", "uuid"),
    _api("Elasticsearch", r"^/_nodes(?:/[^?]*)?$", "cluster_name", "_nodes", "nodes"),
    _api("Elasticsearch", r"^/_cluster/health(?:/[^?]*)?$", "cluster_name", "number_of_nodes", "active_primary_shards"),
    _api("Elasticsearch", r"^/_cluster/state(?:/[^?]*)?$", "cluster_name", "cluster_uuid", "master_node"),
    _api("SCIM", r"^/scim/v2/(?:Users|Groups)/?$",
         r'schemas=\[\s*"urn:ietf:params:scim:api:messages:2\.0:ListResponse"', "totalResults"),
    _api("WordPress REST API users", r"^/wp-json/wp/v2/users/?$", "slug", "avatar_urls", "_links"),
    _api("Grafana", r"^/api/datasources$", "orgId", "isDefault", "basicAuth"),
    _api("Grafana", r"^/api/users$", "login", "isAdmin", "lastSeenAtAge"),
    _api("Grafana", r"^/api/org/users$", "orgId", "userId", "lastSeenAtAge"),
    _api("Grafana", r"^/api/snapshots$", "orgId", "externalUrl", "expires"),
    _api("Consul", r"^/v1/agent/self$", "Config", "Member", "Datacenter"),
    _api("Consul", r"^/v1/kv/[^?]*$", "LockIndex", "CreateIndex", "ModifyIndex"),
    _api("etcd", r"^/v2/keys/[^?]*$", r'action="get"', "modifiedIndex", "createdIndex"),
    _api("Prometheus", r"^/api/v1/status/config$", r'status="success"', "yaml"),
    _api("Prometheus", r"^/api/v1/targets$", r'status="success"', "activeTargets"),
    _api("n8n", r"^/rest/workflows$", r"data=\[", "versionId", "createdAt", "updatedAt"),
    _api("Laravel Horizon", r"^/horizon/api/stats$", "jobsPerMinute", "queueWithMaxRuntime", "recentJobs"),
    _api("Laravel Horizon", r"^/horizon/api/masters$", "supervisors", "pid", "status"),
)


def product_api_for(path: str) -> ProductApi | None:
    """The product management API a route belongs to, or None."""
    route = str(path or "").split("?", 1)[0]
    return next((api for api in PRODUCT_APIS if api.route.match(route)), None)


__all__ = ["PRODUCT_APIS", "ProductApi", "product_api_for"]
