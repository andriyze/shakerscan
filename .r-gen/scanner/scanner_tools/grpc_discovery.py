import shutil
from typing import Any

from .common import run


def _is_reflection_service(name: str) -> bool:
    name_l = (name or "").lower()
    return "grpc.reflection" in name_l or name_l.endswith("serverreflection")


def _parse_grpcurl_output(output: str) -> list[str]:
    return [line.strip() for line in (output or "").splitlines() if line.strip()]


async def _grpcurl_list(address: str, use_tls: bool, timeout: int) -> tuple[list[str], str | None]:
    cmd = ["grpcurl"]
    cmd.append("-insecure" if use_tls else "-plaintext")
    cmd.extend([address, "list"])
    out, err, rc = await run(cmd, timeout=timeout)
    if rc != 0:
        return [], err or out or "grpcurl failed"
    return _parse_grpcurl_output(out), None


async def _grpcurl_list_methods(address: str, service: str, use_tls: bool, timeout: int) -> tuple[list[str], str | None]:
    cmd = ["grpcurl"]
    cmd.append("-insecure" if use_tls else "-plaintext")
    cmd.extend([address, "list", service])
    out, err, rc = await run(cmd, timeout=timeout)
    if rc != 0:
        return [], err or out or "grpcurl failed"
    return _parse_grpcurl_output(out), None


async def grpc_reflection_discovery(
    host: str,
    ports: list[int],
    timeout: int = 8,
    max_services: int = 80,
    max_methods: int = 200,
) -> dict[str, Any]:
    results: dict[str, Any] = {
        "available": False,
        "reflection_supported": False,
        "targets": [],
        "services": [],
        "methods": [],
        "errors": [],
    }

    if not shutil.which("grpcurl"):
        results["errors"].append("grpcurl not installed")
        return results

    results["available"] = True
    services_seen: set[str] = set()
    methods_seen: set[str] = set()

    for port in ports:
        address = f"{host}:{port}"
        target_info = {
            "address": address,
            "port": port,
            "transport": None,
            "services": [],
            "methods": [],
            "errors": [],
        }

        for use_tls in (True, False):
            services, err = await _grpcurl_list(address, use_tls, timeout)
            if err:
                target_info["errors"].append({"transport": "tls" if use_tls else "plaintext", "error": err})
            if not services:
                continue

            target_info["transport"] = "tls" if use_tls else "plaintext"
            filtered_services = [s for s in services if s and not _is_reflection_service(s)]
            if max_services:
                filtered_services = filtered_services[:max_services]
            target_info["services"] = filtered_services
            results["reflection_supported"] = True

            method_count = 0
            for service in filtered_services:
                if max_methods and method_count >= max_methods:
                    break
                methods, method_err = await _grpcurl_list_methods(address, service, use_tls, timeout)
                if method_err:
                    target_info["errors"].append({"service": service, "error": method_err})
                    continue
                for method in methods:
                    if method and method not in target_info["methods"]:
                        target_info["methods"].append(method)
                        method_count += 1
                        if max_methods and method_count >= max_methods:
                            break
            break

        if target_info["services"] or target_info["errors"]:
            results["targets"].append(target_info)
            for service in target_info["services"]:
                services_seen.add(service)
            for method in target_info["methods"]:
                methods_seen.add(method)

    results["services"] = sorted(services_seen)
    results["methods"] = sorted(methods_seen)
    return results
