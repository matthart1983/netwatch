# Egress

Open Egress with `0` in the full view. It learns observed process destinations and compares them with a policy you promote. Review the proposed policy before treating observed traffic as intended behavior.

See the [workflow and keys](@repo@/docs/REFERENCE.md#egress-policy-linter) for learning, promotion and export. Attribution confidence and capture coverage constrain these records; unknown or missed traffic is not proof that no connection occurred.

Egress linting reports policy drift; it is not a firewall enforcement guarantee. See [[eBPF Process Attribution]] and [[Configuration and Privacy]].

<!-- include: docs/REFERENCE.md#egress-policy-linter -->
