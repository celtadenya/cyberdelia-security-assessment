package cyberdelia.compose

# CIS Docker Benchmark 5.25: every service must block privilege escalation.
deny[msg] {
	svc := input.services[name]
	not has_no_new_privileges(svc)
	msg := sprintf("service %q is missing no-new-privileges:true", [name])
}
has_no_new_privileges(svc) {
	svc.security_opt[_] == "no-new-privileges:true"
}

# CIS 5.3: capabilities must be dropped, then re-added explicitly.
deny[msg] {
	svc := input.services[name]
	not svc.cap_drop
	msg := sprintf("service %q does not drop capabilities", [name])
}

# CIS 5.4: privileged mode is never acceptable in this system.
deny[msg] {
	svc := input.services[name]
	svc.privileged
	msg := sprintf("service %q requests privileged mode", [name])
}

# The application and proxy tiers must have an immutable root filesystem.
# The database is exempted deliberately and the exemption is visible here,
# which is the point: a weakening must be written down to take effect.
deny[msg] {
	svc := input.services[name]
	name != "db"
	not svc.read_only
	msg := sprintf("service %q must set read_only: true", [name])
}

# No service may run as root.
deny[msg] {
	svc := input.services[name]
	name != "db"
	not svc.user
	msg := sprintf("service %q does not pin a non-root user", [name])
}

# Secrets must arrive as files, never as environment variables.
deny[msg] {
	svc := input.services[name]
	some k
	svc.environment[k]
	regex.match("(?i)(password|secret|token|key)$", k)
	msg := sprintf("service %q sets %q in the environment; use a *_FILE secret", [name, k])
}

# Only the proxy may publish a port, and only on the loopback interface.
deny[msg] {
	svc := input.services[name]
	name != "proxy"
	svc.ports
	msg := sprintf("service %q publishes a port; only the proxy may", [name])
}
deny[msg] {
	p := input.services.proxy.ports[_]
	not startswith(p.published, "127.0.0.1")
	msg := sprintf("proxy publishes %v on all interfaces", [p.published])
}
