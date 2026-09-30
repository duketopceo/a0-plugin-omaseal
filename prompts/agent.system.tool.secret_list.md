### secret_list

Lists the secret names currently resolvable (keyring `service/account` pairs and vault entries) and which backends are live — omaseal CLI, `op`, environment, plugin vault. Never returns values.

Use this first when a task needs a credential you are not sure exists, then `secret_get` to confirm a specific name.

~~~json
{
    "thoughts": ["Which secrets are available on this host?"],
    "tool_name": "secret_list",
    "tool_args": {}
}
~~~
