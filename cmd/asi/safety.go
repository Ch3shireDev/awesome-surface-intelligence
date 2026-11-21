package main

import (
	"log"
	"strings"
	"sync"

	"asi/internal/safety"
	"asi/internal/targets"
)

// Scanner safety policy (SEC-8), read once from the environment (.env).
var policy = sync.OnceValue(func() *safety.Policy {
	p, err := safety.FromEnv()
	if err != nil {
		log.Fatalf("safety policy: %v", err)
	}
	return p
})

// policyPlan moves hosts the policy forbids from the plan to "skipped", with the reason.
func policyPlan(pol *safety.Policy, plan targets.Plan) targets.Plan {
	ips := make([]string, len(plan.Hosts))
	for i, h := range plan.Hosts {
		ips[i] = h.IP
	}
	_, blocked := pol.Filter(ips)
	if len(blocked) == 0 {
		return plan
	}
	why := map[string]string{}
	for _, b := range blocked {
		why[b.IP] = b.Reason
	}
	kept := plan.Hosts[:0:0]
	for _, h := range plan.Hosts {
		if r, bad := why[h.IP]; bad {
			plan.Skipped = append(plan.Skipped, targets.Skipped{Target: h.IP, Reason: "policy: " + r})
			continue
		}
		kept = append(kept, h)
	}
	plan.Hosts = kept
	return plan
}

// checkNmapArgs fails fast on profile arguments the worker would refuse anyway.
func checkNmapArgs(pol *safety.Policy, name, args string) {
	if _, err := pol.Enforce(strings.Fields(args), safety.Opts{}); err != nil {
		log.Fatalf("%s: %v", name, err)
	}
}
