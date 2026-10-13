# OIDC API Login Requests

This how-to is for an API client author with an active Evydence OIDC provider
and an external OIDC client. It illustrates request shapes; placeholders are
not credentials and this example does not call or verify a real provider.

1. Replace the provider ID in `api-begin.json`, then send that object to
   `POST /v1/sso/authentication-requests`. Keep the returned `state_secret`,
   `nonce` and `authentication_request.id` privately; the request expires in
   five minutes.
2. Send the returned nonce in your external OIDC authorization request and
   obtain a signed ID token through your OIDC client. Evydence does not perform
   redirect orchestration or authorization-code exchange.
3. Replace every placeholder in `api-exchange.json` with that provider ID,
   subject, ID token, request ID and state secret. Send the object to
   `POST /v1/sso/session-exchanges`. API delivery returns a session secret once
   in JSON and sets no cookie. Use it as a bearer credential; avoid logging it.
4. Replaying a committed proof returns `401`. A storage commit failure rolls
   back consumption and permits retry until state/token expiry. If trust
   changes or state expires, restart from step 1.

Use [the canonical login contract](../../docs/api.md#sso-credential-exchange)
for browser cookie delivery, origin protection, key/claim limits, capacity and
error behavior. SAML's standard binding/replay work remains separate.
