from kubernetes import client, config

def load_cluster_connection():
    config.load_kube_config()

def check_privileged_and_root(v1):
    findings = []
    pods = v1.list_pod_for_all_namespaces()
    pods.items = [p for p in pods.items if p.metadata.namespace not in ["kube-system", "kube-public", "kube-node-lease"]]
    for pod in pods.items:
        for container in pod.spec.containers:
            sc = container.security_context
            if sc:
                if sc.privileged:
                    findings.append({
                        "severity": "HIGH",
                        "namespace": pod.metadata.namespace,
                        "pod": pod.metadata.name,
                        "issue": f"Container '{container.name}' runs privileged=true",
                        "remediation": "Set privileged: false in securityContext"
                    })
                if sc.run_as_user == 0:
                    findings.append({
                        "severity": "HIGH",
                        "namespace": pod.metadata.namespace,
                        "pod": pod.metadata.name,
                        "issue": f"Container '{container.name}' runs as root (UID 0)",
                        "remediation": "Set runAsNonRoot: true and runAsUser to non-zero UID"
                    })
        for volume in (pod.spec.volumes or []):
            if volume.host_path:
                findings.append({
                    "severity": "HIGH",
                    "namespace": pod.metadata.namespace,
                    "pod": pod.metadata.name,
                    "issue": f"Pod mounts hostPath volume '{volume.host_path.path}'",
                    "remediation": "Avoid hostPath mounts; use PersistentVolumes instead"
                })
    return findings

def check_resource_limits(v1):
    findings = []
    pods = v1.list_pod_for_all_namespaces()
    pods.items = [p for p in pods.items if p.metadata.namespace not in ["kube-system", "kube-public", "kube-node-lease"]]
    for pod in pods.items:
        for container in pod.spec.containers:
            limits = container.resources.limits if container.resources else None
            if not limits:
                findings.append({
                    "severity": "MEDIUM",
                    "namespace": pod.metadata.namespace,
                    "pod": pod.metadata.name,
                    "issue": f"Container '{container.name}' has no resource limits set",
                    "remediation": "Set resources.limits.cpu and resources.limits.memory"
                })
    return findings

def check_network_policies(v1, networking_v1):
    findings = []
    namespaces = v1.list_namespace()
    policies = networking_v1.list_network_policy_for_all_namespaces()
    namespaces_with_policy = set(p.metadata.namespace for p in policies.items)
    for ns in namespaces.items:
        ns_name = ns.metadata.name
        if ns_name in ["kube-system", "kube-public", "kube-node-lease"]:
            continue
        if ns_name not in namespaces_with_policy:
            findings.append({
                "severity": "MEDIUM",
                "namespace": ns_name,
                "pod": "N/A",
                "issue": "Namespace has no NetworkPolicy defined",
                "remediation": "Create a NetworkPolicy to restrict pod-to-pod traffic"
            })
    return findings

def main():
    load_cluster_connection()
    v1 = client.CoreV1Api()
    networking_v1 = client.NetworkingV1Api()

    all_findings = []
    all_findings += check_privileged_and_root(v1)
    all_findings += check_resource_limits(v1)
    all_findings += check_network_policies(v1, networking_v1)

    print(f"\n{'='*60}")
    print(f"CUSTOM K8S SECURITY SCAN — {len(all_findings)} findings")
    print(f"{'='*60}\n")

    for f in all_findings:
        print(f"[{f['severity']}] {f['namespace']}/{f['pod']}")
        print(f"  Issue: {f['issue']}")
        print(f"  Fix:   {f['remediation']}\n")

if __name__ == "__main__":
    main()