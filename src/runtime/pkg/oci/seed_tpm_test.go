// Copyright (c) 2026 Seed contributors
//
// SPDX-License-Identifier: Apache-2.0
//

package oci

import (
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/stretchr/testify/assert"

	vc "github.com/kata-containers/kata-containers/src/runtime/virtcontainers"
	vcAnnotations "github.com/kata-containers/kata-containers/src/runtime/virtcontainers/pkg/annotations"
)

func TestAddSeedTpmOverrides(t *testing.T) {
	fp := strings.Repeat("ab", 32)
	dir := "/var/lib/seed-controller/tpm/s-gaydazldmnsg-social"

	run := func(ann map[string]string) (vc.SandboxConfig, error) {
		cfg := vc.SandboxConfig{Annotations: map[string]string{}}
		err := addSeedTpmOverrides(specs.Spec{Annotations: ann}, &cfg)
		return cfg, err
	}

	// absent: nothing happens
	cfg, err := run(map[string]string{})
	assert.NoError(t, err)
	assert.Equal(t, "", cfg.HypervisorConfig.SeedTpmMode)

	cfg, err = run(map[string]string{
		vcAnnotations.SeedTpmMode:     "create",
		vcAnnotations.SeedTpmStateDir: dir,
	})
	assert.NoError(t, err)
	assert.Equal(t, "create", cfg.HypervisorConfig.SeedTpmMode)
	assert.Equal(t, dir, cfg.HypervisorConfig.SeedTpmStateDir)

	cfg, err = run(map[string]string{
		vcAnnotations.SeedTpmMode:        "verify",
		vcAnnotations.SeedTpmStateDir:    dir,
		vcAnnotations.SeedTpmFingerprint: fp,
	})
	assert.NoError(t, err)
	assert.Equal(t, fp, cfg.HypervisorConfig.SeedTpmFingerprint)

	bad := []map[string]string{
		{vcAnnotations.SeedTpmMode: "maybe", vcAnnotations.SeedTpmStateDir: dir},
		{vcAnnotations.SeedTpmMode: "create"},
		{vcAnnotations.SeedTpmMode: "create", vcAnnotations.SeedTpmStateDir: "relative/dir"},
		{vcAnnotations.SeedTpmMode: "verify", vcAnnotations.SeedTpmStateDir: dir},
	}
	for _, ann := range bad {
		_, err := run(ann)
		assert.Error(t, err, ann)
	}

	// mutually exclusive with the legacy tpm_socket annotation
	c := vc.SandboxConfig{Annotations: map[string]string{}}
	c.HypervisorConfig.TpmSocket = "/run/swtpm/x/swtpm-sock"
	err = addSeedTpmOverrides(specs.Spec{Annotations: map[string]string{
		vcAnnotations.SeedTpmMode:     "create",
		vcAnnotations.SeedTpmStateDir: dir,
	}}, &c)
	assert.Error(t, err)
}

// The seed.loom.farm/* keys are not io.katacontainers.config.hypervisor.*
// keys, so enable_annotations must not filter them.
func TestSeedTpmAnnotationsNotFiltered(t *testing.T) {
	for _, k := range []string{vcAnnotations.SeedTpmMode, vcAnnotations.SeedTpmStateDir, vcAnnotations.SeedTpmFingerprint} {
		assert.True(t, checkAnnotationNameIsValid([]string{"tpm_socket"}, k, vcAnnotations.KataAnnotationHypervisorPrefix), k)
	}
}
