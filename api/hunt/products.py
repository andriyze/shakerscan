"""The self-hosted products discovery recognises: each one's identity probes and known sensitive routes.

Shared by ``auto_discovery`` (which probes them) and ``server_sweep`` (which treats a recognised
product's routes apart), so neither imports the other.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Product:
    """A product's identity probes, and the known sensitive routes probed once it answers."""

    key: str
    identity: tuple[str, ...]
    routes: tuple[str, ...] = ()
    # Text one identity answer must carry (in its body sample, title or JSON keys) to count;
    # without it, any answer distinct from the control counts.
    marker: str | None = None


PRODUCTS: tuple[Product, ...] = (
    Product("jenkins", ("/jenkins/api/json", "/jenkins/login", "/api/json"),
            ("/jenkins/script", "/jenkins/whoAmI/api/json", "/jenkins/asynchPeople/api/json",
             "/jenkins/people/api/json", "/jenkins/queue/api/json", "/jenkins/computer/api/json",
             "/script", "/whoAmI/api/json", "/asynchPeople/api/json"),
            marker=r"jenkins|hudson|_class"),
    Product("jupyter", ("/api/kernelspecs", "/api/status"),
            ("/api/kernels", "/api/sessions", "/api/terminals", "/api/contents", "/tree", "/lab"),
            marker=r"kernelspecs|kernels|started|last_activity|jupyter"),
    Product("ray", ("/api/cluster_status", "/api/version"),
            ("/api/jobs/", "/api/v0/nodes", "/api/v0/actors", "/api/v0/tasks", "/api/v0/logs",
             "/nodes?view=summary"),
            marker=r"ray|autoscaler|cluster_status"),
    Product("mlflow", ("/api/2.0/mlflow/experiments/search?max_results=1",
                       "/ajax-api/2.0/mlflow/experiments/search?max_results=1"),
            ("/api/2.0/mlflow/registered-models/search", "/ajax-api/2.0/mlflow/registered-models/search",
             "/api/2.0/mlflow/experiments/get-by-name?experiment_name=Default", "/get-artifact",
             "/model-versions/get-artifact"),
            marker=r"experiment"),
    Product("langflow", ("/api/v1/version", "/api/v1/auto_login"),
            ("/api/v1/flows/", "/api/v1/all", "/api/v1/users/whoami", "/api/v1/login",
             "/api/v1/validate/code", "/api/v1/custom_component"),
            marker=r"langflow|access_token|version"),
    Product("flowise", ("/api/v1/ping",), ("/api/v1/chatflows", "/api/v1/credentials", "/api/v1/apikey"),
            marker=r"pong"),
    Product("comfyui", ("/system_stats", "/api/system_stats"),
            ("/object_info", "/queue", "/history", "/api/queue", "/api/history", "/view",
             "/customnode/getlist", "/manager/queue/status"),
            marker=r"system|devices|comfyui|python_version"),
    Product("ollama", ("/api/version", "/api/tags"), ("/api/ps", "/api/show", "/ollama/api/tags"),
            marker=r"version|models"),
    Product("openai_api", ("/v1/models",), ("/v1/usage", "/v1/files", "/v1/chat/completions"),
            marker=r"\bdata\b|object|model"),
    Product("mcp", ("/mcp", "/.well-known/mcp.json"), ("/mcp/tools", "/mcp/resources"),
            marker=r"jsonrpc|tools|mcp|protocol"),
    Product("a2a", ("/.well-known/agent-card.json", "/.well-known/agent.json"), ("/a2a/tasks",),
            marker=r"skills|capabilities|agent"),
    Product("tomcat", ("/manager/html", "/manager/text/list", "/host-manager/html"),
            ("/manager/status", "/manager/text/serverinfo"), marker=None),
    Product("phpmyadmin", ("/phpmyadmin/", "/phpMyAdmin/", "/pma/", "/dbadmin/", "/myadmin/"), (),
            marker=r"phpmyadmin|pma_"),
    Product("wordpress", ("/wp-login.php", "/wp-json/"),
            ("/wp-json/wp/v2/users", "/xmlrpc.php", "/readme.html", "/wp-content/debug.log",
             "/wp-config.php.bak", "/wp-config.php~", "/?author=1"),
            marker=r"wordpress|wp-|namespaces"),
    Product("drupal", ("/core/CHANGELOG.txt", "/CHANGELOG.txt", "/user/login"),
            ("/user/register", "/core/install.php", "/node/1"), marker=r"drupal"),
    Product("joomla", ("/administrator/manifests/files/joomla.xml", "/administrator/"),
            ("/api/index.php/v1/config/application?public=true", "/api/index.php/v1/users?public=true",
             "/configuration.php.bak"), marker=r"joomla"),
    Product("laravel", ("/_ignition/health-check", "/telescope", "/horizon", "/_debugbar/open"),
            ("/storage/logs/laravel.log", "/telescope/telescope-api/requests", "/telescope/requests",
             "/horizon/api/stats", "/_ignition/execute-solution"), marker=None),
    Product("spring", ("/actuator", "/actuator/health"),
            ("/actuator/env", "/actuator/mappings", "/actuator/configprops", "/actuator/logfile",
             "/actuator/beans", "/jolokia/list", "/jolokia/read"), marker=r"_links|status|UP"),
    Product("jolokia", ("/jolokia/", "/jolokia/version"), ("/jolokia/list", "/jolokia/read"),
            marker=r"jolokia|agent|protocol"),
    Product("docker_api", ("/_ping", "/version", "/v1.41/version"),
            ("/info", "/containers/json", "/images/json", "/v1.41/containers/json"),
            marker=r"ApiVersion|OK|Docker"),
    Product("container_registry", ("/v2/",), ("/v2/_catalog",), marker=None),
    Product("kubelet", ("/healthz", "/pods"), ("/runningpods/", "/configz", "/stats/summary", "/spec/"),
            marker=r"PodList|items|ok"),
    Product("kubernetes", ("/api", "/apis", "/k8s/clusters/local/api/v1/namespaces"),
            ("/api/v1/namespaces", "/api/v1/secrets", "/api/v1/pods"), marker=r"APIVersions|versions|kind"),
    Product("etcd", ("/v2/keys/", "/v3/version"), ("/v2/keys/?recursive=true", "/v2/members"),
            marker=r"etcd|node|action"),
    Product("consul", ("/v1/agent/self",), ("/v1/kv/?recurse", "/v1/catalog/services"), marker=r"Config|Member"),
    Product("elasticsearch", ("/_cluster/health",), ("/_cat/indices", "/_nodes"), marker=r"cluster_name"),
    Product("grafana", ("/api/health",), ("/api/datasources", "/api/users", "/api/snapshots"),
            marker=r"database|version"),
    Product("gitlab", ("/api/v4/version", "/users/sign_in"), ("/api/v4/projects", "/explore/projects", "/api/v4/users"),
            marker=r"gitlab|version"),
    Product("prometheus", ("/api/v1/status/buildinfo",), ("/api/v1/status/config", "/api/v1/targets", "/metrics"),
            marker=r"version|success"),
    Product("solr", ("/solr/admin/info/system?wt=json",), ("/solr/admin/cores?wt=json",), marker=r"solr|lucene"),
    Product("n8n", ("/rest/settings",), ("/rest/workflows", "/rest/credentials"), marker=r"data|n8n"),
    Product("exchange", ("/autodiscover/autodiscover.xml", "/EWS/Exchange.asmx", "/owa/"),
            ("/mapi/", "/rpc/", "/_vti_bin/"), marker=None),
    Product("php", ("/phpinfo.php", "/info.php"), ("/php.php", "/test.php", "/debug.php"),
            marker=r"phpinfo|PHP Version|php"),
    Product("apache_status", ("/server-status", "/server-info"), (), marker=r"Apache|Server"),
    Product("scim", ("/scim/v2/ServiceProviderConfig", "/scim/v2/Users"), ("/scim/v2/Groups",),
            marker=r"schemas|Resources|scim"),
    Product("odata", ("/odata/$metadata", "/api/$metadata"), ("/odata/Users",), marker=r"edmx|EntityType"),
    Product("nextjs", (), ("/api/auth/session", "/dashboard", "/admin"), marker=None),
)


__all__ = ["PRODUCTS", "Product"]
