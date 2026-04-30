# PB-SIFT-033 — Container Forensics

**Phase:** Collection / Analysis
**Auto-triggered when:** Docker, containerd, Kubernetes, or Podman artifacts detected
**Specialist:** `container`

## Objective

Analyze Docker containers, container images, and Kubernetes artifacts to detect malicious containers, inspect container filesystems for IOCs, and reconstruct container execution history. Critical for cloud-native incident response and supply-chain attacks.

## Steps

### Container Enumeration (`container.enumerate`)

- List all Docker containers (running, stopped, exited) via `docker ps -a` or filesystem analysis
- Parse `/var/lib/docker/containers/*/config.v2.json` for container metadata
- Extract image name, tag, digest, creation time, command, and environment variables
- Identify containers started during incident window
- Flag containers from untrusted registries or with `latest` tag
- Detect containers running as root (UID 0) or with privileged mode
- Extract container log paths from Docker metadata

### Container Filesystem Extraction (`container.extract_filesystem`)

- Mount or extract container overlayfs layers from `/var/lib/docker/overlay2/`
- Parse `lowerdir`, `upperdir`, and `workdir` from `mount` output
- Extract the merged filesystem view as if the container were running
- Parse container `diff` (changes between image and current state)
- Carve deleted files from container upperdir layers
- Hash all extracted files for malware signature comparison

### Container Image Analysis (`container.analyze_image`)

- Parse Docker image history (`docker history` or manifest.json)
- Inspect image layers for suspicious additions
- Detect images built from known-bad base images
- Check for embedded secrets in image layers (`.env`, `config.json`, `id_rsa`)
- Scan image layer tarballs for malware
- Detect images pulled from non-standard registries during incident window
- Flag images with no digest verification (supply chain risk)

### Container Runtime Logs (`container.analyze_logs`)

- Parse Docker daemon logs (`/var/log/docker.log` or journald)
- Extract container stdout/stderr logs from JSON log files
- Identify suspicious commands executed inside containers
- Detect network connections initiated by containers
- Flag privilege escalation attempts within containers
- Extract `exec` sessions (commands run inside running containers)
- Parse Kubernetes pod logs if cluster artifacts present

### Kubernetes Artifact Analysis (`container.analyze_kubernetes`)

- Parse Kubernetes etcd database (`/var/lib/etcd/`) if accessible
- Extract pod definitions, deployments, and service configurations
- Detect privileged pods, hostPath mounts, and hostNetwork usage
- Identify service accounts with excessive permissions
- Check for suspicious DaemonSets or CronJobs
- Detect lateral movement via Kubernetes API server
- Parse kubelet logs for pod creation/destruction events

### Supply Chain Detection (`container.detect_supply_chain`)

- Compare running container images against known-good registry hashes
- Detect typosquatting in image names (e.g., `nginxx` vs `nginx`)
- Identify images with embedded crypto miners
- Check image build timestamps vs registry pull timestamps
- Detect base image hijacking (malicious layer injected into legitimate image)
- Flag images with no provenance or SBOM (Software Bill of Materials)

## Indicators of Interest

- Container running as root with host filesystem mounted
- Crypto miner binary found in container overlayfs
- Docker socket (`/var/run/docker.sock`) mounted inside container
- Privileged container spawned during incident window
- Image from unknown registry with high CPU usage
- Kubernetes pod with `hostPID: true` or `hostNetwork: true`
- Container `exec` sessions running reconnaissance commands
- Image layers containing SSH keys or cloud credentials
- Supply chain attack: legitimate image replaced with malicious version
- Container escape indicators (cap_sys_admin, seccomp disabled)
- Malicious CronJob running on all nodes via DaemonSet

## Output

```json
{
  "runtime": "Docker 24.0.5",
  "containers_total": 12,
  "containers_running": 3,
  "containers_flagged": 2,
  "images_total": 47,
  "images_flagged": 1,
  "flagged_containers": [
    {
      "id": "a1b2c3d4",
      "image": "ubuntu:latest",
      "privileged": true,
      "host_mounts": ["/", "/var/run/docker.sock"],
      "started": "2024-07-15T02:00:00Z",
      "reason": "Privileged with host root mounted"
    }
  ],
  "malicious_files": [
    "/overlay2/.../merged/tmp/xmrig"
  ],
  "kubernetes": {
    "cluster": true,
    "pods": 23,
    "suspicious_pods": 1,
    "privileged_pods": 2
  },
  "supply_chain_risks": [
    "Image nginx:1.21 digest mismatch with Docker Hub"
  ],
  "findings": []
}
```

## Tools Required

- `docker` CLI — container enumeration (if Docker daemon running)
- `dive` — Docker image layer inspection
- `podman` / `crictl` — alternative container runtime analysis
- `containerd` CLI (`ctr`) — containerd-specific analysis
- `kubectl` — Kubernetes artifact extraction
- `strings` / `find` — overlayfs layer inspection
- `tar` — image layer extraction

## Notes

- Container filesystems are ephemeral — stop and image immediately if suspicious
- Overlayfs layers persist after container deletion (unless `docker rm -v`)
- Docker daemon logs may be in journald — use `journalctl -u docker`
- Kubernetes etcd is a key-value store — parse with `etcdctl` or forensically
- Supply chain attacks are increasingly common — always verify image digests
- Privileged containers = root on host — treat as full host compromise
