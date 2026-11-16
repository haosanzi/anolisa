// Publish before launching Cosh. Only commands requesting network access reach this gate.
@id("case6-network")
@advice("{\"verdict\":\"escalate\",\"message\":\"允许本次命令联网读取 GitHub？\"}")
permit (
    principal is SecCore::Subject,
    action == SecCore::Action::"network.use",
    resource == SecCore::Network::"all"
);
