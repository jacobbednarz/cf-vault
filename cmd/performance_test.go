package cmd

import (
	"fmt"
	"testing"
)

func BenchmarkReadGroups(b *testing.B) {
	groups := make([]permissionGroup, 300)
	for i := range groups {
		groups[i] = permissionGroup{Name: []string{"DNS Read", "DNS Write", "Account API Tokens Read", "Account API Tokens Write", "Security Center Insights"}[i%5]}
	}
	for b.Loop() {
		count := 0
		for _, g := range groups {
			if isReadGroup(g) {
				count++
			}
		}
		if count != 120 {
			b.Fatal(count)
		}
	}
}

func BenchmarkPolicyPreparation(b *testing.B) {
	for _, size := range []int{3, 100} {
		b.Run(fmt.Sprintf("%d_groups_per_policy", size), func(b *testing.B) {
			p := profile{AuthType: authTypeAPIToken, SessionDuration: "15m"}
			for _, resource := range []string{policyResourceAllAccounts, policyResourceAllZones, policyResourceUserPrefix + "user-123"} {
				pol := policy{Effect: policyEffectAllow, Resources: map[string]interface{}{resource: "*"}}
				for i := range size {
					pol.PermissionGroups = append(pol.PermissionGroups, permissionGroup{ID: fmt.Sprintf("%032x", i), Name: "DNS Read"})
				}
				p.Policies = append(p.Policies, pol)
			}
			for b.Loop() {
				if _, _, err := p.prepare(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
