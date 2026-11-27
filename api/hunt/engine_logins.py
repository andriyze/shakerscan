"""The sweep's own logins: accounts it registered, and default credentials it found accepted.

A mixin of ``server_sweep.Sweep`` (it uses the sweep's ``_safe`` call, counters and state). See
``engine_accounts`` for what the engine does with accounts and why.
"""
from __future__ import annotations

import asyncio
from collections.abc import Mapping, Sequence
from typing import Any

from . import engine_accounts as ea

READ_CONCURRENCY = 6


class EngineLogins:
    """``engine_logins``: ``{"label", "bindings", "account", "refs"}`` per login the sweep holds."""

    engine_logins: list[dict[str, Any]]

    def _init_engine_logins(self) -> None:
        self.engine_logins = []
        self.signups_tried: set[str] = set()
        self.login_reads_done: set[tuple[str, str]] = set()
        self.feature_writes_done: set[tuple[str, str, str]] = set()
        self.object_authz_done = False

    def _record(self, key: str, entry: Mapping[str, Any], limit: int = 200) -> None:
        """Append to a clean-up list in the discovery state (the coverage report and debrief show it)."""
        entries = self.state.setdefault(key, [])
        if len(entries) < limit:
            entries.append(dict(entry))

    def adopt_login(self, label: str, bindings: list[dict[str, str]] | None, *,
                    account: Mapping[str, str] | None = None, refs: Mapping[str, str] | None = None) -> None:
        """A login the sweep established (an account it made, a default pair it found accepted)."""
        if not bindings or any(login["bindings"] == bindings for login in self.engine_logins):
            return
        self.engine_logins.append({"label": label, "bindings": bindings, "account": dict(account or {}),
                                   "refs": dict(refs or {})})
        self._count("engine_logins")
        self._stats(engine_logins=[login["label"] for login in self.engine_logins])

    async def _ask_for_accounts(self, items: Sequence[Mapping[str, Any]]) -> bool:
        """Without allow_account_creation: when the target has a registration route, ask (an ordinary
        permission request; a launch bound grants it at once). True once it is granted."""
        routes = [path for path, _params in ea.signup_routes(items)]
        if not routes or self._request_permission is None:
            return False
        try:
            answer = await self._request_permission("account-creation", routes)
        except Exception as exc:  # noqa: BLE001 - asking never stops the sweep
            self._note(f"engine accounts: the permission request failed: {type(exc).__name__}")
            return False
        if answer != "granted":
            self._stats(engine_accounts_permission=answer)
        return answer == "granted"

    async def _make_accounts(self, items: Sequence[Mapping[str, Any]]) -> None:
        """Sign up (at most ``MAX_ACCOUNTS`` accounts) and sign in as each; see ``engine_accounts``."""
        made = sum(1 for login in self.engine_logins if login["label"].startswith("account"))
        for path, params in ea.signup_routes(items):
            if made >= ea.MAX_ACCOUNTS:
                return
            if path in self.signups_tried:
                continue
            self.signups_tried.add(path)
            while made < ea.MAX_ACCOUNTS:
                account = ea.new_account()
                signed_up = await self._sign_up(path, params, account)
                if signed_up is None:
                    break
                login = signed_up if signed_up.get("bindings") else await self._sign_in(account)
                if not login or not login.get("bindings"):
                    self._note(f"engine account: signed up on {path} but could not sign in as it")
                    break
                made += 1
                label = f"account {chr(96 + made)} ({path})"
                self.adopt_login(label, login["bindings"], account=account,
                                 refs={**(signed_up.get("refs") or {}), **(login.get("refs") or {})})
                # For the operator's clean-up: what was made on the target (never the password).
                self._record("engine_accounts", {"label": label, "signup_route": f"POST {path}",
                                                 "email": account["email"], "username": account["username"]})

    async def _sign_up(self, path: str, params: Sequence[str], account: Mapping[str, str]) -> dict[str, Any] | None:
        body = ea.signup_body(params, account)
        for kind in ("json_body", "form_body"):
            # No capture here: a captured answer is hidden from its reader, and the token a sign-up
            # answer carries is read by its withheld reference.
            values = {"method": "POST", "path": path, kind: body, "follow_redirects": False}
            result = await self._safe("http.request", values,
                                      self._key("signup", path, kind, account["email"]))
            response = self._response_of(result)
            status = response.get("status")
            if isinstance(status, int) and 200 <= status < 400:
                token = ea.token_ref(response)
                return {"bindings": ea.bindings_for(token=token, cookie_action=None) if token else None,
                        "refs": ea.own_refs(response)}
            if status not in {400, 415, 422}:
                return None
        return None

    async def _sign_in(self, account: Mapping[str, str]) -> dict[str, Any] | None:
        for path, (_path, user, secret, json_body) in list(self.logins.items())[:4]:
            # One account field per request (the field the form names; a JSON sign-in may sign in by
            # email instead): authz.verify tells two accounts apart by it.
            fields = [user] + (["email"] if json_body and "mail" not in user.lower() else [])
            for field in fields:
                found = await self._sign_in_once(path, field, secret, json_body, account)
                if found:
                    return found
        return None

    async def _sign_in_once(self, path: str, user: str, secret: str, json_body: bool,
                            account: Mapping[str, str]) -> dict[str, Any] | None:
        body = {user: account["email"] if "mail" in user.lower() else account["username"],
                secret: account["password"]}
        values = {"method": "POST", "path": path, ("json_body" if json_body else "form_body"): body,
                  "follow_redirects": False}
        result = await self._safe("http.request", values, self._key("signin", path, user, account["email"]))
        response = self._response_of(result)
        status = response.get("status")
        if not isinstance(status, int) or status >= 400:
            return None
        token = ea.token_ref(response)
        if token:
            return {"bindings": ea.bindings_for(token=token, cookie_action=None), "refs": ea.own_refs(response)}
        if response.get("set_cookie_metadata"):
            # A cookie session: sign in again, capturing it (a captured answer shows no body).
            captured = await self._safe("http.request", {**values, "capture": [
                {"name": "session", "header": "Set-Cookie"}]}, self._key("signin-capture", path, user, account["email"]))
            action = self._action_of(captured)
            if action and isinstance(self._response_of(captured).get("status"), int):
                return {"bindings": ea.bindings_for(token=None, cookie_action=action), "refs": ea.own_refs(response)}
        return None

    async def _use_as_logins(self, items: Sequence[Mapping[str, Any]], *, writes: bool,
                             allowed: set[str]) -> None:
        """Read the mapped routes and send the mapped writes as each engine login; then compare two."""
        if not self.engine_logins:
            return
        gate = asyncio.Semaphore(READ_CONCURRENCY)
        reads = []
        for item in items:
            method, _, route = str(item.get("endpoint") or "").partition(" ")
            if method == "GET" and route.startswith("/") and (
                    route in self.signed_in_only or "{" in route or self._api_route(route)):
                reads.append(route)
        for login in self.engine_logins:
            reads.extend(route for route in ea.derived_object_routes(items, login["refs"]) if route not in reads)
        writes_list = ea.feature_writes(items) if writes else []
        # Writes only as accounts the engine made (never as a default-credential login, which may be
        # a real user's), and only to the account's own objects.
        writers = [login for login in self.engine_logins if login["label"].startswith("account")][:2]

        async def read(login: Mapping[str, Any], route: str) -> None:
            key = (login["label"], route)
            if key in self.login_reads_done or sum(
                    1 for done in self.login_reads_done if done[0] == login["label"]) >= ea.MAX_LOGIN_READS:
                return
            self.login_reads_done.add(key)
            path = ea.concrete_for(route, login["refs"])
            async with gate:
                await self._safe("http.request", {"method": "GET", "path": path, "follow_redirects": False,
                                                  "request_bindings": login["bindings"]},
                                 self._key("login-read", login["label"], path))

        async def write(login: Mapping[str, Any], method: str, route: str, params: Sequence[str]) -> None:
            key = (login["label"], method, route)
            if key in self.feature_writes_done:
                return
            self.feature_writes_done.add(key)
            path = ea.own_path(route, login["refs"])
            if path is None:
                return  # a templated write to an object that is not this account's own
            body = {name: ea.field_value(name, login["account"], login["refs"]) for name in list(params)[:20]}
            self._record("engine_writes", {"login": login["label"], "request": f"{method} {path}",
                                           "fields": sorted(body)[:20]})
            async with gate:
                await self._safe("http.request", {"method": method, "path": path,
                                                  "json_body": body, "follow_redirects": False,
                                                  "request_bindings": login["bindings"]},
                                 self._key("feature", login["label"], method, route))

        jobs = [read(login, route) for login in self.engine_logins for route in reads]
        # Writes as the first two logins: the state each account holds (a basket item, a review).
        jobs += [write(login, *entry) for login in writers for entry in writes_list]
        await asyncio.gather(*jobs)
        if "authz.verify" in allowed:
            await self._compare_logins(items)

    async def _compare_logins(self, items: Sequence[Mapping[str, Any]]) -> None:
        """authz.verify on the routes that name each account's own object, the two logins compared."""
        accounts = [login for login in self.engine_logins if login["label"].startswith("account")]
        if self.object_authz_done or len(accounts) < 2:
            return
        first, second = accounts[0], accounts[1]
        routes: list[str] = []
        derived = [{"endpoint": f"GET {route}"} for route in ea.derived_object_routes(items, first["refs"])]
        for item in [*items, *derived]:
            method, _, route = str(item.get("endpoint") or "").partition(" ")
            if method != "GET" or "{" not in route:
                continue
            mine = ea.own_id(route, first["refs"])
            theirs = ea.own_id(route, second["refs"])
            if mine and theirs and mine != theirs:
                routes.append(ea.concrete_for(route, first["refs"]))
        if not routes:
            return
        self.object_authz_done = True
        for start in range(0, min(len(routes), ea.MAX_OBJECT_ROUTES), 5):
            chunk = routes[start:start + 5]
            await self._safe("authz.verify", {"mode": "object", "routes": chunk,
                                              "primary_bindings": first["bindings"],
                                              "secondary_bindings": second["bindings"]},
                             self._key("engine-authz", *chunk))


__all__ = ["EngineLogins"]
