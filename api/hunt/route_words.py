"""Route names the sweep tries under an API prefix it found (``/api``, ``/api/v1``, ``/rest`` ...).

Authored by the ShakerScan project for this repository (no third-party wordlist content): resource
and action names common to web APIs. Each name is one GET under the prefix, measured against a
negative control under the same prefix; an answer distinct from it (a route that refuses GET with
405 included) enters the inventory, so the sweep reads and tests it. No name here asks a server to
stop, restart, flush or delete anything: a careless API may act on a GET.
"""
from __future__ import annotations

API_ROUTE_WORDS: tuple[str, ...] = tuple(dict.fromkeys("""
users user me profile profiles account accounts admin admins auth login logout register signup
token tokens refresh session sessions password reset-password forgot-password change-password
verify 2fa mfa otp keys api-keys apikeys secrets secret config configuration settings env
environment debug status health healthz ping echo info version metrics stats statistics logs log
audit events history activity notifications messages chat comments comment posts post reviews
feedback search query lookup find filter export import upload uploads download downloads files
file documents docs attachments media images image avatar render template templates preview
convert parse validate xml soap json graphql rpc proxy fetch url redirect callback webhook webhooks
hooks integrations oauth sso saml jwt certificates orders order products product items item cart
checkout payments payment billing invoices invoice transactions transfer transfers wallet balance
withdraw deposit refund subscriptions plans coupons coupon discount inventory catalog categories
tags reports report analytics dashboard tasks jobs queue workers cron schedule backup backups
restore database db sql cache internal private public system tools utils exec execute run command
cmd shell eval script scripts dns resolve network ip host hosts nodes cluster k8s kubernetes pods
containers docker cloud metadata storage buckets objects blobs registry packages sbom dependencies
license tenants tenant organizations orgs teams team groups group roles role permissions acl
policies policy members invite invitations support tickets ticket employees staff customers
customer clients partners vendors projects project apps applications services service features
flags experiments models model ai llm completions embeddings agents agent assistants prompts
functions crypto encrypt decrypt sign hash ldap directory sync bulk batch merge diff compare
translate share links notes calendar booking appointments locations addresses shipping tracking
delivery data records entries collections resources
manager approve impersonate sandbox playground test
""".split()))

# Prefixes worth this list: an API root, optionally versioned.
MAX_API_PREFIXES = 6

__all__ = ["API_ROUTE_WORDS", "MAX_API_PREFIXES"]
