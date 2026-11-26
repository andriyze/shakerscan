"""Route names the sweep tries under an API root it found (``/api``, ``/api/v1``, ``/rest`` ...).

The names are the project's bundled API resource list (``scanner/wordlists/api-resources.txt``,
authored for this repository; the content-discovery ``api`` selection reads the same file at the
target's root), copied here so the API process needs no wordlist file; a test keeps the two equal.
Each name is one GET under the root, measured against a negative control under the same root; an
answer distinct from it (a route that refuses GET with 405 included) enters the inventory, so the
sweep reads and tests it.
"""
from __future__ import annotations

API_ROUTE_WORDS: tuple[str, ...] = tuple(dict.fromkeys("""
shop shop/orders shop/order shop/products shop/product shop/apply_coupon shop/apply-coupon community community/posts community/post community/comments community/comment
coupon/validate coupons/validate apply_coupon apply-coupon validate_coupon validate-coupon auth auth/login auth/logout auth/register auth/signup auth/signin
auth/refresh auth/token auth/verify auth/validate login logout register signup signin token tokens refresh
session sessions me profile profiles account accounts user users users/me users/profile users/settings
password/forgot password/reset password/change password/confirm oauth/token oauth/authorize oauth2/token oauth2/authorize 2fa mfa otp verify
validate products product items item orders order cart basket checkout payments payment
transactions billing invoices invoice subscriptions subscription plans plan pricing price coupons coupon
discounts discount promo promos reviews review feedback comment comments messages message notifications
notification search query filter reports report analytics stats statistics inventory catalog categories
category tags tag upload uploads download downloads file files media assets images
documents attachments export import webhook webhooks callbacks integrations events config settings health
status metrics info version logs audit graphql gql mechanic mechanics vehicle vehicles
contact contacts location locations service services booking bookings appointment appointments workshop garage
repair repairs admin dashboard manage management otp/verify otp/resend otp/generate check posts post
threads thread conversations conversation friends followers following likes shares replies reply notifications/unread
notifications/read preferences privacy security email phone address addresses credit credits wallet balance
history activity recent popular trending featured recommended
""".split()))

# API roots tried per Hunt.
MAX_API_PREFIXES = 3

__all__ = ["API_ROUTE_WORDS", "MAX_API_PREFIXES"]
