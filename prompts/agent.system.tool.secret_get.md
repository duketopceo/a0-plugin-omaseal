### secret_get

Checks whether a named secret exists and returns it **masked** (e.g. `••••••••a1b2`) plus which backend supplied it — omaseal keyring, 1Password `op`, environment variable, or the plugin vault.

The secret's value is never shown to you. To use it, write `§§secret(NAME)` in a later tool call's arguments — the value is substituted at execution time and masked again on the way out.

`name` may be a bare secret name (`OPENROUTER_API_KEY`) or a `service/account` pair (`openrouter/api_key`) for namespaced keyrings.

~~~json
{
    "thoughts": ["The task needs the OpenRouter key — checking it exists before wiring it in."],
    "tool_name": "secret_get",
    "tool_args": { "name": "openrouter/api_key" }
}
~~~
