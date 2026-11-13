// Unified build-report task policy: one file, several consumers.
//
// PAP stores this text as a single Policy revision. Sandbox projects the whole
// file into OS permissions; ActPlane's translator reads the forbid subset. Both
// reference the same policyId + revision, so no second PEP-specific policy is
// authored. Comments state the consumer that relies on each rule.

// Workspace, interpreter and loader reads. Sandbox needs every directory it
// mounts plus the two exact executables. The interpreter entry paths are the
// distro-stable aliases, so no python3.x version is pinned here.
permit(
  principal,
  action == SecCore::Action::"file.read",
  resource is SecCore::File
)
when {
  resource.path == "/srv/br-demo" || resource.path like "/srv/br-demo/*" ||
  resource.path == "/usr/lib" || resource.path like "/usr/lib/*" ||
  resource.path == "/usr/lib64" || resource.path like "/usr/lib64/*" ||
  resource.path == "/lib" || resource.path like "/lib/*" ||
  resource.path == "/lib64" || resource.path like "/lib64/*" ||
  resource.path == "/etc" || resource.path like "/etc/*" ||
  resource.path == "/usr/bin/bash" ||
  resource.path == "/usr/bin/python3"
};

// The only writable region: build outputs and the local report directory.
permit(
  principal,
  action == SecCore::Action::"file.write",
  resource is SecCore::File
)
when {
  resource.path == "/srv/br-demo/releases" ||
  resource.path like "/srv/br-demo/releases/*" ||
  resource.path == "/srv/br-demo/out" ||
  resource.path like "/srv/br-demo/out/*"
};

// Rollback exception: the packaged previous release may be rewritten but never
// deleted. Only the delete operation is forbidden, so a rebuild that overwrites
// the file stays permitted.
forbid(
  principal,
  action == SecCore::Action::"file.write",
  resource is SecCore::File
)
when {
  resource.path == "/srv/br-demo/releases/previous.zip" &&
  context.input.operation == SecCore::WriteOperation::"delete"
};

// The two interpreters the task may start. Sandbox checks this for the initial
// invocation; ActPlane has no process-start target yet.
permit(
  principal,
  action == SecCore::Action::"process.spawn",
  resource is SecCore::Process
)
when {
  resource.program == "bash" || resource.program == "/usr/bin/bash" ||
  resource.program == "python3" || resource.program == "/usr/bin/python3"
};

// No rule permits network.use, so both consumers keep the network closed.
