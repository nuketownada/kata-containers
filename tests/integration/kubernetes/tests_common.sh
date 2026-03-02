#!/bin/bash
#
# Copyright (c) 2021 Red Hat, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script is evoked within an OpenShift Build to product the binary image,
# which will contain the Kata Containers installation into a given destination
# directory.
#
# This contains variables and functions common to all e2e tests.

# Variables used by the kubernetes tests
export container_images_agnhost_name="registry.k8s.io/e2e-test-images/agnhost"
export container_images_agnhost_version="2.21"

# Timeout options, mainly for use with waitForProcess(). Use them unless the
# operation needs to wait longer.
export wait_time=90
export sleep_time=3

# Timeout for use with `kubectl wait`, unless it needs to wait longer.
# Note: try to keep timeout and wait_time equal.
export timeout=90s

# issues that can't test yet.
export fc_limitations="https://github.com/kata-containers/documentation/issues/351"
export dragonball_limitations="https://github.com/kata-containers/kata-containers/issues/6621"

# Path to the kubeconfig file which is used by kubectl and other tools.
# Note: the init script sets that variable but if you want to run the tests in
# your own provisioned cluster and you know what you are doing then you should
# overwrite it.
export KUBECONFIG="${KUBECONFIG:-${HOME}/.kube/config}"

K8S_TEST_DIR="${kubernetes_dir:-"${BATS_TEST_DIRNAME}"}"

AUTO_GENERATE_POLICY="${AUTO_GENERATE_POLICY:-}"
GENPOLICY_PULL_METHOD="${GENPOLICY_PULL_METHOD:-}"
KATA_HYPERVISOR="${KATA_HYPERVISOR:-}"
KATA_HOST_OS="${KATA_HOST_OS:-}"
RUNS_ON_AKS="${RUNS_ON_AKS:-false}"

# Common setup for tests.
#
# Global variables exported:
#	$node	             - random picked node that has kata installed
#	$node_start_date     - start date/time at the $node for the sake of
#                          fetching logs
#
setup_common() {
	node=$(get_one_kata_node)
	[[ -n "${node}" ]]

	node_start_time=$(measure_node_time "${node}")

	export node node_start_time

	k8s_delete_all_pods_if_any_exists || true

	get_pod_config_dir
}

get_pod_config_dir() {
	export pod_config_dir="${BATS_TEST_DIRNAME}/runtimeclass_workloads_work"
	info "k8s configured to use runtimeclass"
}

# Return the first worker found that is kata-runtime labeled.
get_one_kata_node() {
	local resource_name
	resource_name="$(kubectl get node -l katacontainers.io/kata-runtime=true -o name | head -1)"
	# Remove leading "/node"
	echo "${resource_name/"node/"}"
}

auto_generate_policy_enabled() {
	[[ "${AUTO_GENERATE_POLICY}" == "yes" ]]
}

is_coco_platform() {
	case "${KATA_HYPERVISOR}" in
		"qemu-tdx"|"qemu-snp"|"qemu-coco-dev"|"qemu-coco-dev-runtime-rs"|"qemu-nvidia-gpu-tdx"|"qemu-nvidia-gpu-snp")
			return 0
			;;
		*)
			return 1
	esac
}

is_nvidia_gpu_platform() {
	case "${KATA_HYPERVISOR}" in
		qemu-nvidia-gpu*)
			return 0
			;;
		*)
			return 1
	esac
}

is_aks_cluster() {
	if [[ "${RUNS_ON_AKS}" = "true" ]]; then
		return 0
	fi

	return 1
}

is_k3s_or_rke2() {
	case "${KUBERNETES:-}" in
		k3s|rke2) return 0 ;;
		*) return 1 ;;
	esac
}

adapt_common_policy_settings_for_non_coco() {
	local settings_dir=$1

	info "Adapting common policy settings from ${settings_dir} for non-CoCo guest"

	# Using UpdateEphemeralMountsRequest - instead of CopyFileRequest.
	jq '.request_defaults.UpdateEphemeralMountsRequest = true' "${settings_dir}/genpolicy-settings.json" > temp.json
	mv temp.json "${settings_dir}/genpolicy-settings.json"

	# Using a different path to container container root.
	jq '.common.root_path = "/run/kata-containers/shared/containers/$(bundle-id)/rootfs"' "${settings_dir}/genpolicy-settings.json" > temp.json
	mv temp.json "${settings_dir}/genpolicy-settings.json"

	# Using CreateContainer Storage input structs for configMap & secret volumes - instead of using CopyFile like CoCo.
	jq '.kata_config.enable_configmap_secret_storages = true' "${settings_dir}/genpolicy-settings.json" > temp.json
	mv temp.json "${settings_dir}/genpolicy-settings.json"

	# Using watchable binds for configMap volumes - instead of CopyFileRequest.
	jq '.volumes.configMap.mount_point = "^$(cpath)/watchable/$(bundle-id)-[a-z0-9]{16}-" | .volumes.configMap.driver = "watchable-bind"' \
		"${settings_dir}/genpolicy-settings.json" > temp.json
	mv temp.json "${settings_dir}/genpolicy-settings.json"

	# Using a Storage input struct for paths shared with the Host using virtio-fs.
	jq '.sandbox.storages += [{"driver":"virtio-fs","driver_options":[],"fs_group":null,"fstype":"virtiofs","mount_point":"/run/kata-containers/shared/containers/","options":[],"source":"kataShared"}]' \
		"${settings_dir}/genpolicy-settings.json" > temp.json
	mv temp.json "${settings_dir}/genpolicy-settings.json"

	# Disable guest pull.
	jq '.cluster_config.guest_pull = false' "${settings_dir}/genpolicy-settings.json" > temp.json
	mv temp.json "${settings_dir}/genpolicy-settings.json"
}

# adapt common policy settings for AKS Hosts
adapt_common_policy_settings_for_aks() {
	info "Adapting common policy settings for AKS Hosts"

	jq '.pause_container.Process.User.UID = 0' "${settings_dir}/genpolicy-settings.json" > temp.json
	mv temp.json "${settings_dir}/genpolicy-settings.json"

	jq '.pause_container.Process.User.GID = 0' "${settings_dir}/genpolicy-settings.json" > temp.json
	mv temp.json "${settings_dir}/genpolicy-settings.json"

	jq '.cluster_config.pause_container_image = "mcr.microsoft.com/oss/v2/kubernetes/pause:3.6"' "${settings_dir}/genpolicy-settings.json" > temp.json
	mv temp.json "${settings_dir}/genpolicy-settings.json"

	jq '.cluster_config.pause_container_id_policy = "v2"' "${settings_dir}/genpolicy-settings.json" > temp.json
	mv temp.json "${settings_dir}/genpolicy-settings.json"
}

# adapt common policy settings for CBL-Mariner Hosts
adapt_common_policy_settings_for_cbl_mariner() {
	local settings_dir=$1

	info "Adapting common policy settings for KATA_HOST_OS=cbl-mariner"
	jq '.kata_config.oci_version = "1.2.0"' "${settings_dir}/genpolicy-settings.json" > temp.json && mv temp.json "${settings_dir}/genpolicy-settings.json"
}

# Adapt common policy settings for NVIDIA GPU platforms (CI runners use containerd 2.x).
adapt_common_policy_settings_for_nvidia_gpu() {
	local settings_dir=$1

	info "Adapting common policy settings for NVIDIA GPU platform (${KATA_HYPERVISOR})"
	jq '.kata_config.oci_version = "1.2.1"' "${settings_dir}/genpolicy-settings.json" > temp.json && mv temp.json "${settings_dir}/genpolicy-settings.json"
}

# Adapt OCI version in policy settings to match containerd version.
# containerd 2.2.x (active) vendors v1.3.0.
adapt_common_policy_settings_for_containerd_version() {
	local settings_dir=${1}

	info "Adapting common policy settings for containerd's latest release"
	jq '.kata_config.oci_version = "1.3.0"' "${settings_dir}/genpolicy-settings.json" > temp.json && mv temp.json "${settings_dir}/genpolicy-settings.json"
}

# k3s/rke2 use containerd that expects OCI bundle 1.2.1; otherwise autogenerated policy tests fail.
# (Tested with: k3s v1.34.4+k3s1, rke2 v1.34.4+rke2r1.)
adapt_common_policy_settings_for_k3s_rke2() {
	local settings_dir=$1

	info "Adapting common policy settings for k3s/rke2 (OCI bundle 1.2.1)"
	jq '.kata_config.oci_version = "1.2.1"' "${settings_dir}/genpolicy-settings.json" > temp.json && mv temp.json "${settings_dir}/genpolicy-settings.json"
}

# When using experimental-force-guest-pull, genpolicy must not use guest_pull (we pull via oci-distribution for policy generation).
adapt_common_policy_settings_for_experimental_force_guest_pull() {
	local settings_dir=$1

	info "Adapting common policy settings for experimental-force-guest-pull: disable guest_pull"
	jq '.cluster_config.guest_pull = false' "${settings_dir}/genpolicy-settings.json" > temp.json
	mv temp.json "${settings_dir}/genpolicy-settings.json"
}

# Return the drop-in filename to apply for the current scenario (e.g. 10-non-coco-aks-cbl-mariner-drop-in.json),
# or empty string if no scenario drop-in is needed. Used so tests copy the right file from drop-in-examples/.
get_genpolicy_scenario_drop_in_filename() {
	if ! is_coco_platform; then
		if is_aks_cluster && [[ "${KATA_HOST_OS:-}" == "cbl-mariner" ]]; then
			echo "10-non-coco-aks-cbl-mariner-drop-in.json"
		elif is_aks_cluster; then
			echo "10-non-coco-aks-drop-in.json"
		else
			echo "10-non-coco-drop-in.json"
		fi
		return
	fi
	if is_nvidia_gpu_platform || is_k3s_or_rke2; then
		echo "10-oci-1.2.1-drop-in.json"
		return
	fi
	if [[ -n "${CONTAINER_ENGINE_VERSION:-}" ]]; then
		echo "10-oci-1.3.0-drop-in.json"
		return
	fi
	if [[ "${KATA_HOST_OS:-}" == "cbl-mariner" ]]; then
		echo "10-oci-1.2.0-drop-in.json"
		return
	fi
	if [[ "${PULL_TYPE:-}" == "experimental-force-guest-pull" ]]; then
		echo "10-experimental-force-guest-pull-drop-in.json"
		return
	fi
	echo ""
}

# If auto-generated policy testing is enabled, make a copy of the genpolicy settings
# and set up the scenario drop-in. genpolicy is run with -j <dir> so it loads
# genpolicy-settings.json and genpolicy-settings.d/*.json (drop-ins).
create_common_genpolicy_settings() {
	declare -r genpolicy_settings_dir="$1"
	declare -r default_genpolicy_settings_dir="/opt/kata/share/defaults/kata-containers"

	auto_generate_policy_enabled || return 0

	cp "${default_genpolicy_settings_dir}/genpolicy-settings.json" "${genpolicy_settings_dir}"
	cp "${default_genpolicy_settings_dir}/rules.rego" "${genpolicy_settings_dir}"

	mkdir -p "${genpolicy_settings_dir}/genpolicy-settings.d"
	local scenario_drop_in
	scenario_drop_in="$(get_genpolicy_scenario_drop_in_filename)"
	if [[ -n "${scenario_drop_in}" ]] && [[ -f "${default_genpolicy_settings_dir}/drop-in-examples/${scenario_drop_in}" ]]; then
		cp "${default_genpolicy_settings_dir}/drop-in-examples/${scenario_drop_in}" "${genpolicy_settings_dir}/genpolicy-settings.d/"
	fi
}

# If auto-generated policy testing is enabled, make a copy of the common genpolicy settings
# (including genpolicy-settings.d/) into a temporary directory for the current test case.
create_tmp_policy_settings_dir() {
	declare -r common_settings_dir="$1"

	auto_generate_policy_enabled || return 0

	tmp_settings_dir=$(mktemp -d --tmpdir="${common_settings_dir}" genpolicy.XXXXXXXXXX)
	cp "${common_settings_dir}/rules.rego" "${tmp_settings_dir}"
	cp "${common_settings_dir}/genpolicy-settings.json" "${tmp_settings_dir}"
	cp "${common_settings_dir}/default-initdata.toml" "${tmp_settings_dir}"
	if [[ -d "${common_settings_dir}/genpolicy-settings.d" ]]; then
		cp -r "${common_settings_dir}/genpolicy-settings.d" "${tmp_settings_dir}/"
	fi

	echo "${tmp_settings_dir}"
}

# Delete a directory created by create_tmp_policy_settings_dir.
delete_tmp_policy_settings_dir() {
	local settings_dir="$1"

	auto_generate_policy_enabled || return 0

	if [[ -d "${settings_dir}" ]]; then
		info "Deleting ${settings_dir}"
		rm -rf "${settings_dir}"
	fi
}

# Execute genpolicy to auto-generate policy for a test YAML file.
auto_generate_policy() {
	declare -r settings_dir="$1"
	declare -r yaml_file="$2"
	declare -r config_map_yaml_file="${3:-""}"
	declare additional_flags="${4:-""}"

	additional_flags="${additional_flags} --initdata-path=${settings_dir}/default-initdata.toml"

	auto_generate_policy_no_added_flags "${settings_dir}" "${yaml_file}" "${config_map_yaml_file}" "${additional_flags}"
}

auto_generate_policy_no_added_flags() {
	declare -r settings_dir="$1"
	declare -r yaml_file="$2"
	declare -r config_map_yaml_file="${3:-""}"
	declare -r additional_flags="${4:-""}"

	auto_generate_policy_enabled || return 0
	local genpolicy_command="RUST_LOG=info /opt/kata/bin/genpolicy -u -y ${yaml_file}"
	genpolicy_command+=" -p ${settings_dir}/rules.rego"
	genpolicy_command+=" -j ${settings_dir}"

	if [[ -n "${config_map_yaml_file}" ]]; then
		genpolicy_command+=" -c ${config_map_yaml_file}"
	fi

	if [[ "${GENPOLICY_PULL_METHOD}" == "containerd" ]]; then
		genpolicy_command+=" -d"
	fi

	genpolicy_command+=" ${additional_flags}"

	# Retry if genpolicy fails, because typical failures of this tool are caused by
	# transient network errors.
	for _ in {1..6}; do
		info "Executing: ${genpolicy_command}"
		eval "${genpolicy_command}" && return 0
		info "Sleeping after command failed..."
		sleep 10s
	done
	return 1
}

# 99-test-overrides.json is an RFC 6902 JSON Patch (array of ops). We append to it.

# Change genpolicy settings to allow "kubectl exec" to execute a command
# and to read console output from a test pod. Appends an "add" op to 99-test-overrides.json.
add_exec_to_policy_settings() {
	auto_generate_policy_enabled || return 0

	local -r settings_dir="$1"
	shift

	local drop_in_dir="${settings_dir}/genpolicy-settings.d"
	mkdir -p "${drop_in_dir}"
	local overrides_file="${drop_in_dir}/99-test-overrides.json"
	[[ -f "${overrides_file}" ]] || echo '[]' > "${overrides_file}"

	local exec_args
	exec_args=$(printf "%s\n" "$@" | jq -R | jq -sc)
	info "Adding exec allowed_commands to ${overrides_file}: ${exec_args}"
	jq --argjson args "${exec_args}" \
		'. + [{"op":"add","path":"/request_defaults/ExecProcessRequest/allowed_commands/-","value":$args}]' \
		"${overrides_file}" > "${overrides_file}.tmp" && mv "${overrides_file}.tmp" "${overrides_file}"
}

# Change genpolicy settings to allow one or more ttrpc requests from the Host to the Guest.
# Appends "replace" ops to 99-test-overrides.json.
add_requests_to_policy_settings() {
	declare -r settings_dir="$1"
	shift
	declare -r requests=("$@")

	auto_generate_policy_enabled || return 0

	local drop_in_dir="${settings_dir}/genpolicy-settings.d"
	mkdir -p "${drop_in_dir}"
	local overrides_file="${drop_in_dir}/99-test-overrides.json"
	[[ -f "${overrides_file}" ]] || echo '[]' > "${overrides_file}"

	for request in "${requests[@]}"; do
		info "Allowing ${request} in ${overrides_file}"
		jq --arg req "${request}" '. + [{"op":"replace","path":("/request_defaults/" + $req),"value":true}]' \
			"${overrides_file}" > "${overrides_file}.tmp" && mv "${overrides_file}.tmp" "${overrides_file}"
	done
}

# Change genpolicy settings to allow executing on the Guest VM the commands
# used by "kubectl cp" from the Host to the Guest.
add_copy_from_host_to_policy_settings() {
	local -r genpolicy_settings_dir="$1"

	local exec_command=(test -d /tmp)
	add_exec_to_policy_settings "${genpolicy_settings_dir}" "${exec_command[@]}"
	exec_command=(tar -xmf - -C /tmp)
	add_exec_to_policy_settings "${genpolicy_settings_dir}" "${exec_command[@]}"
}

# Change genpolicy settings to allow executing on the Guest VM the commands
# used by "kubectl cp" from the Guest to the Host.
add_copy_from_guest_to_policy_settings() {
	local -r genpolicy_settings_dir="$1"
	local -r copied_file="$2"

	exec_command=(tar cf - "${copied_file}")
	add_exec_to_policy_settings "${genpolicy_settings_dir}" "${exec_command[@]}"
}

hard_coded_policy_tests_enabled() {
	local enabled="no"
	# CI is testing hard-coded policies just on a the platforms listed here. Outside of CI,
	# users can enable testing of the same policies (plus the auto-generated policies) by
	# specifying AUTO_GENERATE_POLICY=yes.
	local -r enabled_hypervisors=("qemu-coco-dev" "qemu-snp" "qemu-tdx" "qemu-coco-dev-runtime-rs")
	for enabled_hypervisor in "${enabled_hypervisors[@]}"
	do
		if [[ "${enabled_hypervisor}" == "${KATA_HYPERVISOR}" ]]; then
			enabled="yes"
			break
		fi
	done

	if [[ "${enabled}" == "no" && "${KATA_HOST_OS}" == "cbl-mariner" ]]; then
		enabled="yes"
	fi

	if [[ "${enabled}" == "no" ]] && auto_generate_policy_enabled; then
		enabled="yes"
	fi

	[[ "${enabled}" == "yes" ]]
}

encode_policy_in_init_data() {
  local input="$1"   # either a filename or a policy
  local POLICY

  # if input is a file, read its contents
  if [[ -f "${input}" ]]; then
    POLICY="$(< "${input}")"
  else
    POLICY="${input}"
  fi

  cat <<EOF | gzip -c | base64 -w0
version = "0.1.0"
algorithm = "sha256"

[data]
"policy.rego" = '''
${POLICY}
'''
EOF
}

# ALLOW_ALL_POLICY is a Rego policy that allows all the Agent ttrpc requests.
ALLOW_ALL_POLICY="${ALLOW_ALL_POLICY:-$(encode_policy_in_init_data "${K8S_TEST_DIR}/../../../src/kata-opa/allow-all.rego")}"

add_allow_all_policy_to_yaml() {
	hard_coded_policy_tests_enabled || return 0

	local yaml_file="$1"
	# Previous version of yq was not ready to handle multiple objects in a single yaml.
	# By default was changing only the first object.
	# With yq>4 we need to make it explicit during the read and write.
	local resource_kind
	resource_kind=$(yq eval 'select(documentIndex == 0) | .kind' "${yaml_file}")

	case "${resource_kind}" in
	Pod)
		info "Adding allow all policy to ${resource_kind} from ${yaml_file}"
		yq -i \
			".metadata.annotations.\"io.katacontainers.config.hypervisor.cc_init_data\" = \"${ALLOW_ALL_POLICY}\"" \
      "${yaml_file}"
		;;

	Deployment|Job|ReplicationController)
		info "Adding allow all policy to ${resource_kind} from ${yaml_file}"
		yq -i \
			".spec.template.metadata.annotations.\"io.katacontainers.config.hypervisor.cc_init_data\" = \"${ALLOW_ALL_POLICY}\"" \
      "${yaml_file}"
		;;

	List)
		die "Issue #7765: adding allow all policy to ${resource_kind} from ${yaml_file} is not implemented yet"
		;;

	ConfigMap|LimitRange|Namespace|PersistentVolume|PersistentVolumeClaim|RuntimeClass|Secret|Service)
		info "Policy is not required for ${resource_kind} from ${yaml_file}"
		;;

	*)
		die "k8s resource type ${resource_kind} from ${yaml_file} is not yet supported for policy testing"
		;;

	esac
}

# Execute "kubectl describe ${pod}" in a loop, until its output contains "${endpoint} is blocked by policy"
wait_for_blocked_request() {
	local -r endpoint="$1"
	local -r pod="$2"

	local -r command="kubectl describe pod ${pod} | grep \"${endpoint} is blocked by policy\""
	info "Waiting ${wait_time} seconds for: ${command}"
	waitForProcess "${wait_time}" "${sleep_time}" "${command}" >/dev/null 2>/dev/null
}

# Execute in a pod a command that is allowed by policy.
pod_exec_allowed_command() {
	local -r pod_name="$1"
	shift

	local -r exec_output=$(kubectl exec "${pod_name}" -- "${@}" 2>&1)

	local -r exec_args=$(printf '"%s",' "${@}")
	info "Pod ${pod_name}: <${exec_args::-1}>:"
	info "${exec_output}"

	(echo "${exec_output}" | grep "policy") && die "exec was blocked by policy!"
	return 0
}

# Execute in a pod a command that is blocked by policy.
pod_exec_blocked_command() {
	local -r pod_name="$1"
	shift

	local -r exec_output=$(kubectl exec "${pod_name}" -- "${@}" 2>&1)

	local -r exec_args=$(printf '"%s",' "${@}")
	info "Pod ${pod_name}: <${exec_args::-1}>:"
	info "${exec_output}"

	(echo "${exec_output}" | grep "ExecProcessRequest is blocked by policy" > /dev/null) || die "exec was not blocked by policy!"
}

# Common teardown for tests.
#
# Parameters:
#	$1	- node name where kata is installed
#	$2	- start time at the node for the sake of fetching logs
#
teardown_common() {
	local node="$1"
	local node_start_time="$2"

	kubectl describe pods
	k8s_delete_all_pods_if_any_exists || true

	local node_end_time
	node_end_time=$(measure_node_time "${node}")

	echo "Journal LOG starts at ${node_start_time:-}, ends at ${node_end_time:-}"

	# Print the node journal since the test start time if a bats test is not completed
	if [[ -n "${node_start_time}" && -z "${BATS_TEST_COMPLETED}" ]]; then
		echo "DEBUG: system logs of node '${node}' since test start time (${node_start_time})"
		exec_host "${node}" journalctl -x -t "kata" --since '"'"${node_start_time}"'"' || true
	fi
}

measure_node_time() {
	local node="$1"
	[[ -n "${node}" ]]

	local node_time
	node_time=$(exec_host "${node}" date +\"%Y-%m-%d %H:%M:%S\")
	local count=0
	while [[ -z "${node_time}" ]] && [[ "${count}" -lt 3 ]]; do
		echo "node_time is empty, trying again..."
		sleep 2
		node_time=$(exec_host "${node}" date +\"%Y-%m-%d %H:%M:%S\")
		count=$((count + 1))
	done
	[[ -n "${node_time}" ]]

	printf '%s\n' "${node_time}"
}

# Execute a command in a pod and grep kubectl's output.
#
# Parameters:
#	$1	- pod name
#	$2	- the grep pattern
#	$3+	- the command to execute using "kubectl exec"
#
# Exit code:
#	Equal to grep's exit code
grep_pod_exec_output() {
	local -r pod_name="$1"
	shift
	local -r grep_arg="$1"
	shift
	pod_exec "${pod_name}" "$@" | grep "${grep_arg}"
}

# Execute a command in a pod and echo kubectl's output to stdout.
#
# Parameters:
#	$1	- pod name
#	$2+	- the command to execute using "kubectl exec"
#
# Exit code:
#	0
pod_exec() {
	local -r pod_name="$1"
	shift
	local -r container_name=""

	container_exec "${pod_name}" "${container_name}" "$@"
}

# Execute a command in a pod's container and echo kubectl's output to stdout.
#
# If the caller specifies an empty container name as parameter, the command is executed in pod's default container,
# or in pod's first container if there is no default.
#
# Parameters:
#	$1	- pod name
#	$2	- container name
#	$3+	- the command to execute using "kubectl exec"
#
# Exit code:
#	0
container_exec() {
	local -r pod_name="$1"
	shift
	local -r container_name="$1"
	shift
	local cmd_out=""

	if [[ -n "${container_name}" ]]; then
		bats_unbuffered_info "Executing in pod ${pod_name}, container ${container_name}: $*"
		if ! cmd_out=$(kubectl exec "${pod_name}" -c "${container_name}" -- "$@"); then
			bats_unbuffered_info "kubectl exec failed"
			cmd_out=""
			# preserve failure semantics: return kubectl's exit code
			return 1
		fi
	else
		bats_unbuffered_info "Executing in pod ${pod_name}: $*"
		if ! cmd_out=$(kubectl exec "${pod_name}" -- "$@"); then
			bats_unbuffered_info "kubectl exec failed"
			cmd_out=""
			# preserve failure semantics: return kubectl's exit code
			return 1
		fi
	fi

	if [[ -n "${cmd_out}" ]]; then
		bats_unbuffered_info "command output: ${cmd_out}"
	else
		bats_unbuffered_info "Warning: empty output from kubectl exec"
	fi

	echo "${cmd_out}"
}

set_nginx_image() {
	input_yaml=$1
	output_yaml=$2

	ensure_yq
	nginx_registry=$(get_from_kata_deps ".docker_images.nginx.registry")
	nginx_digest=$(get_from_kata_deps ".docker_images.nginx.digest")
	nginx_image="${nginx_registry}@${nginx_digest}"

	NGINX_IMAGE="${nginx_image}" envsubst < "${input_yaml}" > "${output_yaml}"
}

print_node_journal_since_test_start() {
	local node="${1}"
	local node_start_time="${2:-}"
	local BATS_TEST_COMPLETED="${3:-}"

	if [[ -n "${node_start_time:-}" && -z "${BATS_TEST_COMPLETED:-}" ]]; then
		echo "DEBUG: system logs of node '${node}' since test start time (${node_start_time})"
		exec_host "${node}" journalctl -x -t "kata" --since '"'"${node_start_time}"'"' || true
	fi
}
