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

    def adopt_login(self, label: str, bindings: list[dict[str, str]] | None, *,
                    account: Mapping[str, str] | None = None, refs: Mapping[str, str] | None = None) -> None:
        """A login the sweep established (an account it made, a default pair it found accepted)."""
        if not bindings or any(login["bindings"] == bindings for login in self.engine_logins):
            return
        self.engine_logins.append({"label": label, "bindings": bindings, "account": dict(account or {}),
                                   "refs": dict(refs or {})})
        self._count("engine_logins")
        self._stats(engine_logins=[login["label"] for login in self.engine_logins])

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
                self.adopt_login(f"account {chr(96 + made)} ({path})", login["bindings"], account=account,
                                 refs={**(signed_up.get("refs") or {}), **(login.get("refs") or {})})

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
            body = {user: account["email"] if "mail" in user.lower() else account["username"],
                    secret: account["password"]}
            if json_body:
                # A JSON sign-in may name its account by email or by user name: send both.
                body.setdefault("email", account["email"])
                body.setdefault("username", account["username"])
            values = {"method": "POST", "path": path, ("json_body" if json_body else "form_body"): body,
                      "follow_redirects": False}
            result = await self._safe("http.request", values, self._key("signin", path, account["email"]))
            response = self._response_of(result)
            status = response.get("status")
            if not isinstance(status, int) or status >= 400:
                continue
            token = ea.token_ref(response)
            if token:
                return {"bindings": ea.bindings_for(token=token, cookie_action=None), "refs": ea.own_refs(response)}
            if response.get("set_cookie_metadata"):
                # A cookie session: sign in again, capturing it (a captured answer shows no body).
                captured = await self._safe("http.request", {**values, "capture": [
                    {"name": "session", "header": "Set-Cookie"}]}, self._key("signin-capture", path, account["email"]))
                action = self._action_of(captured)
                if action and isinstance(self._response_of(captured).get("status"), int):
                    return {"bindings": ea.bindings_for(token=None, cookie_action=action),
                            "refs": ea.own_refs(response)}
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
        writes_list = ea.feature_writes(items) if writes else []

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
            body = {name: ea.field_value(name, login["account"], login["refs"]) for name in list(params)[:20]}
            async with gate:
                await self._safe("http.request", {"method": method, "path": ea.concrete_for(route, login["refs"]),
                                                  "json_body": body, "follow_redirects": False,
                                                  "request_bindings": login["bindings"]},
                                 self._key("feature", login["label"], method, route))

        jobs = [read(login, route) for login in self.engine_logins for route in reads]
        # Writes as the first two logins: the state each account holds (a basket item, a review).
        jobs += [write(login, *entry) for login in self.engine_logins[:2] for entry in writes_list]
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
        for item in items:
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
