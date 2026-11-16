// Both files must be private to the administrator at import time.
@id("case6-github-user")
@modify("inject_credential")
@real_token_file("/root/gh-test.token")
@fake_token_file("/root/gh-demo-fake.token")
@inject_header("Authorization")
@inject_format("auto")
@response_rewrite("true")
permit (
    principal,
    action == SecCore::Action::"network.send",
    resource is SecCore::HttpEndpoint
)
when {
    resource.host == "api.github.com" &&
    context.input.scheme == "https" &&
    context.input.method == "GET" &&
    context.input.path == "/user"
};
