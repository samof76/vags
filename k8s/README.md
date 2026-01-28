# Kubernetes the Hard Way

### Created the [Vagrantfile](./Vagrantfile) with following instances

- Loadbalancer - `lb`  (TODO: Need to move the api server to this.)
- Control Plane - `cp`
- Worker Node 1 - `w1`
- Worker Node 2 - `w2`

The vagrant does the following:
- Sets up the following instances with their static IP addresses:
  - Loadbalancer (`lb`) with IP address `10.10.10.10`
  - Control Plane (`cp`) with IP address `10.10.10.11`
  - Worker Node 1 (`w1`) with IP address `10.10.10.12`
  - Worker Node 2 (`w2`) with IP address `10.10.10.13`
- The local [`shared/dl`](./shared/dl) folder is shared mounted on all instance at `/downloads`
- Sets up the port forwarding for the host to 6443 to instance 6443 for `cp1` and `lb` instances
- Sets up the `/etc/hosts` file on each instance with the following entries:
  - `lb` with IP address `10.10.10.10`
  - `cp` with IP address `10.10.10.11`
  - `w1` with IP address `10.10.10.12`
  - `w2` with IP address `10.10.10.13`
- Sets up inter instance ssh keys for `vagrant` user
- Sets up host access to root user using `root.pub` (NOTE: You would need to replace it with your id_rsa.pub)

### Download the Kubernetes artifacts using the following command

```bash
wget -q --show-progress \
        --https-only \
        --timestamping \
        -P shared/dl \
        -i downloads-$(dpkg --print-architecture).txt
```

### Organize the downloaded files into the appropriate directories

```bash
{
  ARCH=$(dpkg --print-architecture)
  mkdir -p shared/dl/{client,cni-plugins,controller,worker}
  tar -xvf shared/dl/crictl-v1.32.0-linux-${ARCH}.tar.gz \
    -C shared/dl/worker/
  tar -xvf shared/dl/containerd-2.1.0-beta.0-linux-${ARCH}.tar.gz \
    --strip-components 1 \
    -C shared/dl/worker/
  tar -xvf shared/dl/cni-plugins-linux-${ARCH}-v1.6.2.tgz \
  -C shared/dl/cni-plugins/
  tar -xvf shared/dl/etcd-v3.6.0-rc.3-linux-${ARCH}.tar.gz \
     -C shared/dl/ \
    --strip-components 1 \
    etcd-v3.6.0-rc.3-linux-${ARCH}/etcdctl \
    etcd-v3.6.0-rc.3-linux-${ARCH}/etcd
  mv shared/dl/{etcdctl,kubectl} shared/dl/client/
  mv shared/dl/{etcd,kube-apiserver,kube-controller-manager,kube-scheduler} \
  shared/dl/controller/
  mv shared/dl/{kubelet,kube-proxy} shared/dl/worker/
  mv shared/dl/runc.${ARCH} shared/dl/worker/runc
}
```

At this point reload the vagrant instances

```bash
vagrant reload
```

### Creating the PKI certificates from [`ca.conf`](./ca.conf), generate the CA configuration file, certificate, and private key:

```bash
{
  openssl genrsa -out ca.key 4096
  openssl req -x509 -new -sha512 -noenc \
    -key ca.key -days 3653 \
    -config ca.conf \
    -out ca.crt
}
```

and generate the certificates and private keys:

```bash
certs=(
  "admin" "w1" "w2"
  "kube-proxy" "kube-scheduler"
  "kube-controller-manager"
  "kube-api-server"
  "service-accounts"
)
# Now for he looping
for i in ${certs[*]}; do
  openssl genrsa -out "${i}.key" 4096

  openssl req -new -key "${i}.key" -sha256 \
    -config "ca.conf" -section ${i} \
    -out "${i}.csr"

  openssl x509 -req -days 3653 -in "${i}.csr" \
    -copy_extensions copyall \
    -sha256 -CA "ca.crt" \
    -CAkey "ca.key" \
    -CAcreateserial \
    -out "${i}.crt"
done
```

copy these files into the worker nodes:

```bash
for host in w1 w2; do
  ssh root@${host} mkdir /var/lib/kubelet/

  scp ca.crt root@${host}:/var/lib/kubelet/

  scp ${host}.crt \
    root@${host}:/var/lib/kubelet/kubelet.crt

  scp ${host}.key \
    root@${host}:/var/lib/kubelet/kubelet.key
done
```

copy appropriate certs into the control plane nodes:

```bash
scp \
  ca.key ca.crt \
  kube-api-server.key kube-api-server.crt \
  service-accounts.key service-accounts.crt \
  root@cp1:~/
```

### Generate the kubernetes configuration files for the authentication

> When generating kubeconfig files for Kubelets the client certificate matching the Kubelet's node name must be used. This will ensure Kubelets are properly authorized by the Kubernetes [Node Authorizer](https://kubernetes.io/docs/reference/access-authn-authz/node/).

Generate a kubeconfig file for the node-0 and node-1 worker nodes:

```bash
for host in w1 w2; do
  kubectl config set-cluster kubernetes-the-hard-way \
    --certificate-authority=ca.crt \
    --embed-certs=true \
    --server=https://cp1.kubernetes.local:6443 \
    --kubeconfig=${host}.kubeconfig

  kubectl config set-credentials system:node:${host} \
    --client-certificate=${host}.crt \
    --client-key=${host}.key \
    --embed-certs=true \
    --kubeconfig=${host}.kubeconfig

  kubectl config set-context default \
    --cluster=kubernetes-the-hard-way \
    --user=system:node:${host} \
    --kubeconfig=${host}.kubeconfig

  kubectl config use-context default \
    --kubeconfig=${host}.kubeconfig
done
```

Generate kubeconfig file for the `kube-proxy` service:

```bash
kubectl config set-cluster kubernetes-the-hard-way \
  --certificate-authority=ca.crt \
  --embed-certs=true \
  --server=https://cp1.kubernetes.local:6443 \
  --kubeconfig=kube-proxy.kubeconfig

kubectl config set-credentials system:kube-proxy \
  --client-certificate=kube-proxy.crt \
  --client-key=kube-proxy.key \
  --embed-certs=true \
  --kubeconfig=kube-proxy.kubeconfig

kubectl config set-context default \
  --cluster=kubernetes-the-hard-way \
  --user=system:kube-proxy \
  --kubeconfig=kube-proxy.kubeconfig

kubectl config use-context default \
  --kubeconfig=kube-proxy.kubeconfig
```

Generate a kubeconfig file for the `kube-controller-manager` service:

```bash
kubectl config set-cluster kubernetes-the-hard-way \
  --certificate-authority=ca.crt \
  --embed-certs=true \
  --server=https://cp1.kubernetes.local:6443 \
  --kubeconfig=kube-controller-manager.kubeconfig

kubectl config set-credentials system:kube-controller-manager \
  --client-certificate=kube-controller-manager.crt \
  --client-key=kube-controller-manager.key \
  --embed-certs=true \
  --kubeconfig=kube-controller-manager.kubeconfig

kubectl config set-context default \
  --cluster=kubernetes-the-hard-way \
  --user=system:kube-controller-manager \
  --kubeconfig=kube-controller-manager.kubeconfig

kubectl config use-context default \
  --kubeconfig=kube-controller-manager.kubeconfig
```

Generate a kubeconfig file for the `kube-scheduler` service:

```bash
kubectl config set-cluster kubernetes-the-hard-way \
  --certificate-authority=ca.crt \
  --embed-certs=true \
  --server=https://cp1.kubernetes.local:6443 \
  --kubeconfig=kube-scheduler.kubeconfig

kubectl config set-credentials system:kube-scheduler \
  --client-certificate=kube-scheduler.crt \
  --client-key=kube-scheduler.key \
  --embed-certs=true \
  --kubeconfig=kube-scheduler.kubeconfig

kubectl config set-context default \
  --cluster=kubernetes-the-hard-way \
  --user=system:kube-scheduler \
  --kubeconfig=kube-scheduler.kubeconfig

kubectl config use-context default \
  --kubeconfig=kube-scheduler.kubeconfig
```

Generate a kubeconfig file for the `admin` user:

```bash
kubectl config set-cluster kubernetes-the-hard-way \
  --certificate-authority=ca.crt \
  --embed-certs=true \
  --server=https://127.0.0.1:6443 \
  --kubeconfig=admin.kubeconfig

kubectl config set-credentials admin \
  --client-certificate=admin.crt \
  --client-key=admin.key \
  --embed-certs=true \
  --kubeconfig=admin.kubeconfig

kubectl config set-context default \
  --cluster=kubernetes-the-hard-way \
  --user=admin \
  --kubeconfig=admin.kubeconfig

kubectl config use-context default \
  --kubeconfig=admin.kubeconfig
```

Distribute the Kubernetes Configuration Files

Copy the kubelet and kube-proxy kubeconfig files to the w1 and w2 machines:

```bash
for host in w1 w2; do
  ssh root@${host} "mkdir -p /var/lib/{kube-proxy,kubelet}"

  scp kube-proxy.kubeconfig \
    root@${host}:/var/lib/kube-proxy/kubeconfig \

  scp ${host}.kubeconfig \
    root@${host}:/var/lib/kubelet/kubeconfig
done
```

Copy the kube-controller-manager and kube-scheduler kubeconfig files to the cp1 machine:

```bash
scp admin.kubeconfig \
  kube-controller-manager.kubeconfig \
  kube-scheduler.kubeconfig \
  root@cp1:~/
```

### Generating the Data Encryption Config and Key

> Kubernetes stores a variety of data including cluster state, application configurations, and secrets. Kubernetes supports the ability to encrypt cluster data at rest.

Encryption key:

```bash
export ENCRYPTION_KEY=$(head -c 32 /dev/urandom | base64)
```

Encryption configuration:

```yaml
envsubst < encryption-config.yaml.tmpl > encryption-config.yaml
```

Copy to cp1:

```bash
scp encryption-config.yaml root@cp1:~/
```

### Bootstrap the etcd Cluster

> Kubernetes components are stateless and store cluster state in etcd

> **NOTE**: This exercise only sets up single node etcd cluster, which is no where close to a production setup.



```bash
scp etcd.service root@cp1:~/
# Execute the following commands on the `cp1`
# I mean `ssh root@cp1`
# 1. Copy the controller into the PATH
cp /downloads/controller/etcd /usr/local/bin/
# 2. Copy the client cli tool into PATH
cp /downloads/client/etcdctl /usr/local/bin/
# 3. Create etcd required directories
mkdir -p /etc/etcd /var/lib/etcd
# 4. Set appropriate permissions data directory
chmod 700 /var/lib/etcd
# 5. Copy the crt, key files into the config folder
cp ca.crt kube-api-server.crt kube-api-server.key /etc/etcd/
# 6. Copy the etcd service file into the systemd folder
cp etcd.service /etc/systemd/system/
# 7. Reload the systemd daemon
systemctl daemon-reload
# 8. Enable the etcd service to start on boot
systemctl enable etcd
# 9. Start the etcd service
systemctl start etcd
# 10. Verify the etcd service is running
systemctl status etcd
# 11. Verify using etcdctl
etcdctl member list
```

> You need to test this with an `vagrant reload` ensure it works.

### Bootstrapping the Kubernetes Control Plane

> Kubernetes API Server, Scheduler, and Controller Manager components will be installed on the `cp1` machine.

Copy or move the relevant files into or on the `cp1` machine.

```bash
# SCP the unit files.
scp kube-apiserver.service \
  kube-controller-manager.service \
  kube-scheduler.service \
  kube-scheduler.yaml \
  kube-apiserver-to-kubelet.yaml \
  root@cp1:~/
# Execute the following commands on the `cp1`
# I mean `ssh root@cp1`
# 1. Copy the controllers to the PATH
cp /downloads/controller/kube-apiserver /usr/local/bin/
cp /downloads/controller/kube-controller-manager /usr/local/bin/
cp /downloads/controller/kube-scheduler /usr/local/bin/
# 2. Copy the cli client tool to the PATH
cp /downloads/client/kubectl /usr/local/bin/
# 3. Create Kubernetes config directory
mkdir -p /etc/kubernetes/config
```

Configure kubernetes api-server

```bash
# 1. Create Kubernetes folder
mkdir -p /var/lib/kubernetes
# 2. Copy the  API server crt, key files into the Kubernetes folder
cp ca.crt ca.keykube-api-server.crt kube-api-server.key  /var/lib/kubernetes/
# 3. Copy the service account crt and key files into the Kubernetes folder
cp service-accounts.crt service-accounts.key /var/lib/kubernetes/
# 4. Copy the encryption config file into the Kubernetes folder
cp encryption-config.yaml /var/lib/kubernetes/
# 5. Copy the unit file into systemd folder
cp kube-apiserver.service /etc/systemd/system/
```

Configure the kubernetes controller manager

```bash
# 1. Create Kubernetes folder
mkdir -p /var/lib/kubernetes
# 2. Copy the  API server crt, key files into the Kubernetes folder
cp kube-controller-manager.kubeconfig /var/lib/kubernetes/
# 3. Copy the unit file into systemd folder
cp kube-controller-manager.service /etc/systemd/system/
```

Configure the kubernetes scheduler

```bash
# 1. Create Kubernetes folder
mkdir -p /var/lib/kubernetes
# 2. Copy the  API server crt, key files into the Kubernetes folder
cp kube-scheduler.kubeconfig /var/lib/kubernetes/
# 3. Copy the Kubernetes Scheduler configuration file kubernetes config folder
cp kube-scheduler.yaml /etc/kubernetes/config/
# 3. Copy the unit file into systemd folder
cp kube-scheduler.service /etc/systemd/system/
```

Start the Controller Services

```bash
# 1. Reload systemd configuration
systemctl daemon-reload
# 2. Enable the services
systemctl enable kube-apiserver kube-controller-manager kube-scheduler
# 3. Start the services
systemctl start kube-apiserver kube-controller-manager kube-scheduler
```

> VERIFICATION: You need to verify of the services are active, running and without any errors. Then we should sheck the apiserver is reachable using the kubectl command.

```bash
# 1. Verify the services are active
systemctl is-active kube-apiserver kube-controller-manager kube-scheduler
# 2. Verify the services are running
systemctl status kube-apiserver kube-controller-manager kube-scheduler
# 3. Verify the services are without errors
journalctl -u kube-apiserver
journalctl -u kube-controller-manager
journalctl -u kube-scheduler
# 4. Verify the apiserver is reachable using the kubectl command
kubectl get componentstatuses --kubeconfig admin.kubeconfig
# 5. Verify the cluster information
kubectl cluster-info --kubeconfig admin.kubeconfig
```

**Moving on to RBAC for Kubelet Authorization**

> Configure RBAC permissions to allow the Kubernetes API Server to access the Kubelet API on each worker node. Access to the Kubelet API is required for retrieving metrics, logs, and executing commands in pods.

```bash
# Execute the following commands on the `cp1`
# I mean `ssh root@cp1`
kubectl apply -f kube-apiserver-to-kubelet.yaml --kubeconfig admin.kubeconfig
```

> VERIFICATION: Should be done on the host.

```bash
# Execute the following command on the host
curl --cacert ca.crt https://cp1.kubernetes.local:6443/version
# Should produce the following output
# {
#   "major": "1",
#   "minor": "32",
#   "gitVersion": "v1.32.3",
#   "gitCommit": "32cc146f75aad04beaaa245a7157eb35063a9f99",
#   "gitTreeState": "clean",
#   "buildDate": "2025-03-11T19:52:21Z",
#   "goVersion": "go1.23.6",
#   "compiler": "gc",
#   "platform": "linux/amd64"
# }
```

### Bootstrapping the Kubernetes Worker Nodes

> Configure the kubernetes worker nodes `w1` and `w2` by manually installing the `kubelet`, `kube-proxy`, `crictl`, `containerd`, and `runc` packages.

Copy the configurations files into the worker nodes

```bash
# Run this from the host
for HOST in w1 w2; do
  SUBNET=$(grep ${HOST} machines.txt | cut -d " " -f 4)
  sed "s|SUBNET|$SUBNET|g" \
    10-bridge.conf.tmpl > 10-bridge.conf

  scp 10-bridge.conf kubelet-config.yaml \
  root@${HOST}:~/
  rm -rf 10-bridge.conf
  scp \
    99-loopback.conf \
    containerd-config.toml \
    kube-proxy-config.yaml \
    containerd.service \
    kubelet.service \
    kube-proxy.service \
    root@${HOST}:~/
done
```

The following commands needs to be run on w1

```bash
# Login to w1 before running the following commands
# ssh root@w1(or w2)
# 1. Install some os dependencies
dnf install -y socat conntrack-tools ipset kmod
# 2. Check if the swap in on
swapon --show
# 3. IF the above output shows swap is on, disable it
swapoff -a
# 4. Create the installation directories
mkdir -p \
  /etc/cni/net.d \
  /opt/cni/bin \
  /var/lib/kubelet \
  /var/lib/kube-proxy \
  /var/lib/kubernetes \
  /etc/containerd \
  /var/run/kubernetes
# 5. Install(copy) the worker binaries into the appropriate location
cp /downloads/worker/crictl \
  /downloads/worker/kube-proxy \
  /downloads/worker/kubelet \
  /downloads/worker/runc \
  /usr/local/bin/
cp /downloads/worker/containerd \
  /downloads/worker/containerd-shim-runc-v2 \
  /downloads/worker/containerd-stress \
  /bin/
# 6. Install(copy) the cni plugins into the appropriate location
cp /downloads/cni-plugins/* /opt/cni/bin/
# 7. Copy the cni configuration files into the appropriate location
cp 10-bridge.conf 99-loopback.conf /etc/cni/net.d/
# 8. To ensure network traffic crossing the CNI bridge network 
# is processed by iptables, load and configure the br-netfilter kernel module
modprobe br_netfilter
# 9. Enable the br_netfilter module to persist across reboots
echo "br_netfilter" >> /etc/modules-load.d/br_netfilter.conf
# 10. Send bridged traffic through iptables so Kubernetes NetworkPolicies can work.
# NOTE: These only work if `br_netfilter` module is loaded
echo "net.bridge.bridge-nf-call-iptables = 1" \
  >> /etc/sysctl.d/kubernetes.conf
echo "net.bridge.bridge-nf-call-ip6tables = 1" \
  >> /etc/sysctl.d/kubernetes.conf
sysctl --system
# 11. Setup containerd
cp containerd-config.toml /etc/containerd/config.toml
cp containerd.service /etc/systemd/system/
# 12. Setup Kubelet service
cp kubelet-config.yaml /var/lib/kubelet/
cp kubelet.service /etc/systemd/system/
# 13. Setup KubeProxy service
cp kube-proxy-config.yaml /var/lib/kube-proxy/
cp kube-proxy.service /etc/systemd/system/
# 14. Enable and start the worker services
systemctl daemon-reload
systemctl enable containerd kubelet kube-proxy
systemctl start containerd kubelet kube-proxy
```

The above steps have to be done for the `w2` worker node as well.

> VERIFICATION: Login to `cp1` and run the following command to verify that the worker nodes are ready:

```bash
# Login to cp1 before running the following commands
# ssh root@cp1
kubectl get nodes --kubeconfig admin.kubeconfig
```

### Configuring kubectl for Remote Access

> You will generate a kubeconfig file for the kubectl command line utility based on the admin user credentials. And all these commands must be run from the host machine.

Verfify the connectivito to `cp1`

```bash
curl --cacert ca.crt https://cp1.kubernetes.local:6443/version
# You should find an output similar to this...
# {
#   "major": "1",
#   "minor": "32",
#   "gitVersion": "v1.32.3",
#   "gitCommit": "32cc146f75aad04beaaa245a7157eb35063a9f99",
#   "gitTreeState": "clean",
#   "buildDate": "2025-03-11T19:52:21Z",
#   "goVersion": "go1.23.6",
#   "compiler": "gc",
#   "platform": "linux/amd64"
# }
```

Generate a kubeconfig file suitable for authenticating as the `admin` user:

```bash
kubectl config set-cluster kubernetes-the-hard-way \
  --certificate-authority=ca.crt \
  --embed-certs=true \
  --server=https://cp1.kubernetes.local:6443

kubectl config set-credentials admin \
  --client-certificate=admin.crt \
  --client-key=admin.key

kubectl config set-context kubernetes-the-hard-way \
  --cluster=kubernetes-the-hard-way \
  --user=admin

kubectl config use-context kubernetes-the-hard-way
```

> VERIFICATION: Take kubectl for a ride to check `version` and `nodes`

```bash
kubectl version
# The output should look like this...
# Client Version: v1.33.1
# Kustomize Version: v5.6.0
# Server Version: v1.32.3
kubectl get nodes
# The output should look like this...
# NAME   STATUS   ROLES    AGE    VERSION
# w1     Ready    <none>   123m   v1.32.3
# w2     Ready    <none>   11m    v1.32.3
```

### Provisioning Pod Network Routes

> Pods scheduled to a node receive an IP address from the node's Pod CIDR range. At this point pods can not communicate with other pods running on different nodes due to missing network routes.

```bash
# Get the Internal IP and Pod CIDR

CP1_IP=$(grep cp1 machines.txt | cut -d " " -f 1)
W1_IP=$(grep w1 machines.txt | cut -d " " -f 1)
W1_SUBNET=$(grep w1 machines.txt | cut -d " " -f 4)
W2_IP=$(grep w2 machines.txt | cut -d " " -f 1)
W2_SUBNET=$(grep w2 machines.txt | cut -d " " -f 4)
```

Add routes on `cp1` node

```bash
ssh root@cp1 <<EOF
  ip route add ${W1_SUBNET} via ${W1_IP}
  ip route add ${W2_SUBNET} via ${W2_IP}
EOF
```

Add routes on `w1` node

```bash
ssh root@w1 <<EOF
  ip route add ${W2_SUBNET} via ${W2_IP}
EOF
```

Add routes on `w2` node

```bash
ssh root@w2 <<EOF
  ip route add ${W1_SUBNET} via ${W1_IP}
EOF
```

### Smoke Test

Lets create a secret and verify it.

```bash
# Run this from the host machine
kubectl create secret generic kubernetes-the-hard-way \
  --from-literal="mykey=mydata"
```

To verify use `hexdump` tool

```bash
# Run this on `cp1`
etcdctl get /registry/secrets/default/kubernetes-the-hard-way | hexdump -C
# The etcd key should be prefixed with `k8s:enc:aescbc:v1:key1`, 
# which indicates the `aescbc` provider was used to encrypt 
# the data with the `key1` encryption key.
# 00000000  2f 72 65 67 69 73 74 72  79 2f 73 65 63 72 65 74  |/registry/secret|
# 00000010  73 2f 64 65 66 61 75 6c  74 2f 6b 75 62 65 72 6e  |s/default/kubern|
# 00000020  65 74 65 73 2d 74 68 65  2d 68 61 72 64 2d 77 61  |etes-the-hard-wa|
# 00000030  79 0a 6b 38 73 3a 65 6e  63 3a 61 65 73 63 62 63  |y.k8s:enc:aescbc|
# 00000040  3a 76 31 3a 6b 65 79 31  3a 34 a4 93 f9 78 71 bd  |:v1:key1:4...xq.|
# 00000050  c8 62 88 5e ae 23 45 e3  69 eb d6 0a 1f 8b 4b 32  |.b.^.#E.i.....K2|
# 00000060  d0 5c 41 a6 c3 d5 28 30  99 bf cb 61 93 56 19 b5  |.\A...(0...a.V..|
# 00000070  74 e8 17 bb cd a4 a3 9b  ef 88 e2 75 2d b8 b6 af  |t..........u-...|
# 00000080  ab 3b f3 1a cb 71 92 80  fc 62 8d b9 29 6f 67 69  |.;...q...b..)ogi|
# 00000090  18 d1 a4 4c 91 fa 3d a3  48 ae e0 d0 b3 ae a7 f9  |...L..=.H.......|
# 000000a0  c1 e1 67 57 52 ed 77 87  23 bb da d8 15 60 3a 6f  |..gWR.w.#....`:o|
# 000000b0  7e be 66 4c ae f1 5e 29  f9 9c bf f2 77 71 ea 47  |~.fL..^)....wq.G|
# 000000c0  49 65 d2 9d 04 94 a3 81  dc c0 16 47 ad 75 77 8c  |Ie.........G.uw.|
# 000000d0  4c b7 80 36 ea 7f 02 a8  09 e3 85 70 03 47 a1 34  |L..6.......p.G.4|
# 000000e0  85 89 ef 0a b8 ab f8 a8  b8 21 74 38 36 7e f0 b9  |.........!t86~..|
# 000000f0  f0 ee 24 70 2b df d7 65  79 4c 27 9e f8 21 a1 c5  |..$p+..eyL'..!..|
# 00000100  05 49 06 9d 46 f0 e0 8f  f0 37 7d 90 18 25 4e a8  |.I..F....7}..%N.|
# 00000110  95 25 ed f6 37 5b 87 61  22 1a b3 d1 d0 a9 c8 3a  |.%..7[.a"......:|
# 00000120  cb 04 d0 01 2d 3b 48 de  74 23 8f d0 7f b6 4b 45  |....-;H.t#....KE|
# 00000130  5d aa b4 9f ab 64 d0 ba  e2 45 a3 30 1f 8b f6 2f  |]....d...E.0.../|
# 00000140  9e b2 6c 3e f1 74 da 78  57 1a 1c 97 da 17 13 d9  |..l>.t.xW.......|
# 00000150  28 e5 02 85 86 85 85 60  41 0a                    |(......`A.|
# 0000015a
```

Lets deploy something, running the following command from the host

```bash
# The following command must be run from the host
kubectl create deployment nginx \
  --image=nginx:latest
# List the pod created by the nginx deployment
kubectl get pods -l app=nginx
# Should see an output like this...
# NAME                     READY   STATUS    RESTARTS   AGE
# nginx-54c98b4f84-gvkb9   1/1     Running   0          79s

```

> VERIFICATION: Let's forward and test

```bash
# The following commands must be run from the host
POD_NAME=$(kubectl get pods -l app=nginx \
  -o jsonpath="{.items[0].metadata.name}")

kubectl port-forward $POD_NAME 8888:80
curl --head http://127.0.0.1:8888
# Should see an output like this...
# HTTP/1.1 200 OK
# Server: nginx/1.29.4
# Date: Mon, 26 Jan 2026 17:00:49 GMT
# Content-Type: text/html
# Content-Length: 615
# Last-Modified: Tue, 09 Dec 2025 18:28:10 GMT
# Connection: keep-alive
# ETag: "69386a3a-267"
# Accept-Ranges: bytes
# 
# Check the logs of the pod
kubectl logs $POD_NAME
# Should see a line like this...
# 127.0.0.1 - - [26/Jan/2026:17:00:49 +0000] "HEAD / HTTP/1.1" 200 0 "-" "curl/7.81.0" "-"
```

Lets create a node port service for our nginx deployment

```bash
# The following command must be run from the host
kubectl expose deployment nginx \
  --port 80 --type NodePort
# Retrieve the node port
NODE_PORT=$(kubectl get svc nginx \
  --output=jsonpath='{range .spec.ports[0]}{.nodePort}')
# Retrieve the node name
NODE_NAME=$(kubectl get pods \
  -l app=nginx \
  -o jsonpath="{.items[0].spec.nodeName}")
# Now curl with this data
curl -I http://${NODE_NAME}:${NODE_PORT}
# Should see an output like this...
# HTTP/1.1 200 OK
# Server: nginx/1.29.4
# Date: Mon, 26 Jan 2026 17:08:17 GMT
# Content-Type: text/html
# Content-Length: 615
# Last-Modified: Tue, 09 Dec 2025 18:28:10 GMT
# Connection: keep-alive
# ETag: "69386a3a-267"
# Accept-Ranges: bytes
```

### TODO

- Multi node control plane
- Implementation of Load Balancing
