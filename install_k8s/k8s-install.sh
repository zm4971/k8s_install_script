#!/bin/bash 
#

master_nodes=()
worker_nodes=()
all_nodes=()
##etcd_hosts=(192.168.0.11 192.168.0.12 192.168.0.13)
etcd_hosts=()
k8s_version="1.13.4"
#service_cidr="10.255.0.1/16"
service_cidr=
service_dns=
pod_cidr=

#生成证书文件
kubenetes_serviceip=$(echo "$service_cidr"|awk  -F'/' '{print $1}')
cat >k8s-root-ca-csr.json <<EOF
{
    "CN": "kubernetes",
    "key": {
        "algo": "rsa",
        "size": 4096
    },
    "names": [
        {
            "C": "CN",
            "ST": "Sichuan",
            "L": "Chengdu",
            "O": "kubernetes",
            "OU": "System"
        }
    ],
    "ca": {
        "expiry": "87600h"
    }
}
EOF

cat > k8s-gencert.json <<EOF1
{
    "signing": {
        "default": {
            "expiry": "87600h"
        },
        "profiles": {
            "kubernetes": {
                "usages": [
                    "signing",
                    "key encipherment",
                    "server auth",
                    "client auth"
                ],
                "expiry": "87600h"
            }
        }
    }
}
EOF1

cat > kube-apiserver-csr.json <<EOF2
{
    "CN": "kubernetes",
    "hosts": [
        "127.0.0.1",
        "$kubenetes_serviceip",
        "localhost",
        "*.master.kubernetes.node",
        "kubernetes",
        "kubernetes.default",
        "kubernetes.default.svc",
        "kubernetes.default.svc.cluster",
        "kubernetes.default.svc.cluster.local"
    ],
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C": "CN",
            "ST": "Sichuan",
            "L": "Chengdu",
            "O": "kubernetes",
            "OU": "System"
        }
    ]
}
EOF2

cat > kube-controller-manager-csr.json << EOF3
{
  "CN": "system:kube-controller-manager",
  "hosts": [
    "127.0.0.1",
    "localhost",
    "*.master.kubernetes.node"
  ],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "ST": "Sichuan",
      "L": "Chengdu",
      "O": "system:kube-controller-manager",
      "OU": "System"
    }
  ]
}
EOF3

cat > kube-scheduler-csr.json << EOF4
{
  "CN": "system:kube-scheduler",
  "hosts": [
    "127.0.0.1",
    "localhost",
    "*.master.kubernetes.node"
  ],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "ST": "Sichuan",
      "L": "Chengdu",
      "O": "system:kube-scheduler",
      "OU": "System"
    }
  ]
}
EOF4

cat > kube-proxy-csr.json << EOF5
{
    "CN": "system:kube-proxy",
    "hosts": [],
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C": "CN",
            "ST": "Sichuan",
            "L": "Chengdu",
            "O": "system:kube-proxy",
            "OU": "System"
        }
    ]
}
EOF5

cat > kubelet-api-admin-csr.json << EOF6
{
    "CN": "system:kubelet-api-admin",
    "hosts": [],
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C": "CN",
            "ST": "Sichuan",
            "L": "Chengdu",
            "O": "system:kubelet-api-admin",
            "OU": "System"
        }
    ]
}
EOF6

cat > admin.json << EOF7
{
    "CN": "system:masters",
    "hosts": [],
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C": "CN",
            "ST": "Sichuan",
            "L": "Chengdu",
            "O": "system:masters",
            "OU": "System"
        }
    ]
}
EOF7

#生成证书文件
cfssl gencert --initca=true k8s-root-ca-csr.json | cfssljson --bare k8s-root-ca

for targetName in kube-apiserver kube-controller-manager kube-scheduler kube-proxy kubelet-api-admin admin; do
    cfssl gencert --ca k8s-root-ca.pem --ca-key k8s-root-ca-key.pem --config k8s-gencert.json --profile kubernetes $targetName-csr.json | cfssljson --
bare $targetName
done

mkdir -p ssl
mv *.pem ssl/

#本机获取kubectl命令 
curl https://storage.googleapis.com/kubernetes-release/release/v${k8s_version}/bin/linux/amd64/kubectl -o /usr/bin/kubectl
chmod +x /usr/bin/kubectl

#生成kubeconfig文件
# 指定 apiserver 地址
KUBE_APISERVER="https://127.0.0.1:6443"

# 生成 Bootstrap Token
BOOTSTRAP_TOKEN_ID=$(head -c 6 /dev/urandom | md5sum | head -c 6)
BOOTSTRAP_TOKEN_SECRET=$(head -c 16 /dev/urandom | md5sum | head -c 16)
BOOTSTRAP_TOKEN="${BOOTSTRAP_TOKEN_ID}.${BOOTSTRAP_TOKEN_SECRET}"
echo "Bootstrap Tokne: ${BOOTSTRAP_TOKEN}"

# 生成 kubelet tls bootstrap 配置
echo "Create kubelet bootstrapping kubeconfig..."
kubectl config set-cluster kubernetes \
  --certificate-authority=k8s-root-ca.pem \
  --embed-certs=true \
  --server=${KUBE_APISERVER} \
  --kubeconfig=bootstrap.kubeconfig
kubectl config set-credentials "system:bootstrap:${BOOTSTRAP_TOKEN_ID}" \
  --token=${BOOTSTRAP_TOKEN} \
  --kubeconfig=bootstrap.kubeconfig
kubectl config set-context default \
  --cluster=kubernetes \
  --user="system:bootstrap:${BOOTSTRAP_TOKEN_ID}" \
  --kubeconfig=bootstrap.kubeconfig
kubectl config use-context default --kubeconfig=bootstrap.kubeconfig

# 生成 kube-controller-manager 配置文件
echo "Create kube-controller-manager kubeconfig..."
kubectl config set-cluster kubernetes \
  --certificate-authority=k8s-root-ca.pem \
  --embed-certs=true \
  --server=${KUBE_APISERVER} \
  --kubeconfig=kube-controller-manager.kubeconfig
kubectl config set-credentials "system:kube-controller-manager" \
  --client-certificate=kube-controller-manager.pem \
  --client-key=kube-controller-manager-key.pem \
  --embed-certs=true \
  --kubeconfig=kube-controller-manager.kubeconfig
kubectl config set-context default \
  --cluster=kubernetes \
  --user=system:kube-controller-manager \
  --kubeconfig=kube-controller-manager.kubeconfig
kubectl config use-context default --kubeconfig=kube-controller-manager.kubeconfig 

# 生成 kube-scheduler 配置文件
echo "Create kube-scheduler kubeconfig..."
kubectl config set-cluster kubernetes \
  --certificate-authority=k8s-root-ca.pem \
  --embed-certs=true \
  --server=${KUBE_APISERVER} \
  --kubeconfig=kube-scheduler.kubeconfig
kubectl config set-credentials "system:kube-scheduler" \
  --client-certificate=kube-scheduler.pem \
  --client-key=kube-scheduler-key.pem \
  --embed-certs=true \
  --kubeconfig=kube-scheduler.kubeconfig
kubectl config set-context default \
  --cluster=kubernetes \
  --user=system:kube-scheduler \
  --kubeconfig=kube-scheduler.kubeconfig
kubectl config use-context default --kubeconfig=kube-scheduler.kubeconfig 

# 生成 kube-proxy 配置文件
echo "Create kube-proxy kubeconfig..."
kubectl config set-cluster kubernetes \
  --certificate-authority=k8s-root-ca.pem \
  --embed-certs=true \
  --server=${KUBE_APISERVER} \
  --kubeconfig=kube-proxy.kubeconfig
kubectl config set-credentials "system:kube-proxy" \
  --client-certificate=kube-proxy.pem \
  --client-key=kube-proxy-key.pem \
  --embed-certs=true \
  --kubeconfig=kube-proxy.kubeconfig
kubectl config set-context default \
  --cluster=kubernetes \
  --user=system:kube-proxy \
  --kubeconfig=kube-proxy.kubeconfig
kubectl config use-context default --kubeconfig=kube-proxy.kubeconfig 

# 生成 apiserver RBAC 审计配置文件 
cat >> audit-policy.yaml <<EOF8
# Log all requests at the Metadata level.
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
- level: Metadata
EOF8

# 生成 tls bootstrap token secret 配置文件
cat >> bootstrap.secret.yaml <<EOF9
apiVersion: v1
kind: Secret
metadata:
  # Name MUST be of form "bootstrap-token-<token id>"
  name: bootstrap-token-${BOOTSTRAP_TOKEN_ID}
  namespace: kube-system
# Type MUST be 'bootstrap.kubernetes.io/token'
type: bootstrap.kubernetes.io/token
stringData:
  # Human readable description. Optional.
  description: "The default bootstrap token."
  # Token ID and secret. Required.
  token-id: ${BOOTSTRAP_TOKEN_ID}
  token-secret: ${BOOTSTRAP_TOKEN_SECRET}
  # Expiration. Optional.
  expiration: $(date -d'+2 day' -u +"%Y-%m-%dT%H:%M:%SZ")
  # Allowed usages.
  usage-bootstrap-authentication: "true"
  usage-bootstrap-signing: "true"
  # Extra groups to authenticate the token as. Must start with "system:bootstrappers:"
#  auth-extra-groups: system:bootstrappers:worker,system:bootstrappers:ingress
EOF9

#下载k8s hypekube文件【下载太慢可以手动下载后上传到该目录】
    if [ ! -f "hyperkube" ]; then
        curl -L https://storage.googleapis.com/kubernetes-release/release/v${KUBE_VERSION}/bin/linux/amd64/hyperkube
    fi

#创建特定用户以及相关目录
for i in ${all_nodes[*]}
do 
   scp hyperkube $i:/usr/local/bin
   ssh $i "useradd kube -s /sbin/nologin;mkdir -p /etc/kubernetes/ssl;chmod 755 /etc/kubernetes/ssl;mkdir /var/log/kube-audit;mkdir /var/lib/kubelet;mkdir /usr/libexec;chown -R kube:kube /etc/kubernetes /var/log/kube-audit /var/lib/kubelet /usr/libexec;chmod +x /usr/local/bin/*;/usr/local/bin/hyperkube --make-symlinks"    
done 

#创建相关配置文件
#服务文件
cat > kube-apiserver.service <<EOFS1
[Unit]
Description=Kubernetes API Server
Documentation=https://github.com/GoogleCloudPlatform/kubernetes
After=network.target
After=etcd.service

[Service]
EnvironmentFile=-/etc/kubernetes/apiserver
User=kube
ExecStart=/usr/local/bin/kube-apiserver \\
	    $KUBE_LOGTOSTDERR \\
	    $KUBE_LOG_LEVEL \\
	    $KUBE_ETCD_SERVERS \\
	    $KUBE_API_ADDRESS \\
	    $KUBE_API_PORT \\
	    $KUBELET_PORT \\
	    $KUBE_ALLOW_PRIV \\
	    $KUBE_SERVICE_ADDRESSES \\
	    $KUBE_ADMISSION_CONTROL \\
	    $KUBE_API_ARGS
Restart=on-failure
Type=notify
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOFS1

cat > kube-controller-manager.service <<EOFS2
[Unit]
Description=Kubernetes Controller Manager
Documentation=https://github.com/GoogleCloudPlatform/kubernetes

[Service]
EnvironmentFile=-/etc/kubernetes/controller-manager
User=kube
ExecStart=/usr/local/bin/kube-controller-manager \\
	    $KUBE_LOGTOSTDERR \\
	    $KUBE_LOG_LEVEL \\
	    $KUBE_MASTER \\
	    $KUBE_CONTROLLER_MANAGER_ARGS
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOFS2

cat > kube-scheduler.service <<EOFS3
[Unit]
Description=Kubernetes Scheduler Plugin
Documentation=https://github.com/GoogleCloudPlatform/kubernetes

[Service]
EnvironmentFile=-/etc/kubernetes/scheduler
User=kube
ExecStart=/usr/local/bin/kube-scheduler \\
	    $KUBE_LOGTOSTDERR \\
	    $KUBE_LOG_LEVEL \\
	    $KUBE_MASTER \\
	    $KUBE_SCHEDULER_ARGS
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOFS3

cat > kubelet.service << EOFS4
[Unit]
Description=Kubernetes Kubelet Server
Documentation=https://github.com/GoogleCloudPlatform/kubernetes
After=docker.service
Requires=docker.service

[Service]
WorkingDirectory=/var/lib/kubelet
EnvironmentFile=-/etc/kubernetes/kubelet
ExecStart=/usr/local/bin/kubelet \\
	    $KUBE_LOGTOSTDERR \\
	    $KUBE_LOG_LEVEL \\
	    $KUBELET_API_SERVER \\
	    $KUBELET_ADDRESS \\
	    $KUBELET_PORT \\
	    $KUBELET_HOSTNAME \\
	    $KUBE_ALLOW_PRIV \\
	    $KUBELET_ARGS
Restart=on-failure
KillMode=process

[Install]
WantedBy=multi-user.target
EOFS4

cat > kube-proxy.service << EOFS5
[Unit]
Description=Kubernetes Kube-Proxy Server
Documentation=https://github.com/GoogleCloudPlatform/kubernetes
After=network.target

[Service]
EnvironmentFile=-/etc/kubernetes/proxy
ExecStart=/usr/local/bin/kube-proxy \\
	    $KUBE_LOGTOSTDERR \\
	    $KUBE_LOG_LEVEL \\
	    $KUBE_MASTER \\
	    $KUBE_PROXY_ARGS
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOFS5

#配置文件
a_string=$(for j in ${etcd_hosts[*]}
do 
  echo "https://"$j":2379,"
done)

etcd_address=`echo $a_string | sed  's/ //g'|sed 's/.$//g'`
cat > apiserver << EOFS6
###
# kubernetes system config
#
# The following values are used to configure the kube-apiserver
#

# The address on the local server to listen to.
KUBE_API_ADDRESS="--advertise-address=\$node_ip --bind-address=0.0.0.0"

# The port on the local server to listen on.
KUBE_API_PORT="--secure-port=6443"

# Port minions listen on
# KUBELET_PORT="--kubelet-port=10250"

# Comma separated list of nodes in the etcd cluster
KUBE_ETCD_SERVERS="--etcd-servers=$etcd_address"

# Address range to use for services
KUBE_SERVICE_ADDRESSES="--service-cluster-ip-range='$service_cidr'"

# default admission control policies
KUBE_ADMISSION_CONTROL="--enable-admission-plugins=NamespaceLifecycle,LimitRanger,ServiceAccount,DefaultStorageClass,DefaultTolerationSeconds,MutatingAdmissionWebhook,ValidatingAdmissionWebhook,Priority,ResourceQuota"

# Add your own!
KUBE_API_ARGS=" --allow-privileged=true \\
                --anonymous-auth=false \\
                --alsologtostderr \\
                --apiserver-count=3 \\
                --audit-log-maxage=30 \\
                --audit-log-maxbackup=3 \\
                --audit-log-maxsize=100 \\
                --audit-log-path=/var/log/kube-audit/audit.log \\
                --audit-policy-file=/etc/kubernetes/audit-policy.yaml \\
                --authorization-mode=Node,RBAC \\
                --client-ca-file=/etc/kubernetes/ssl/k8s-root-ca.pem \\
                --enable-bootstrap-token-auth \\
                --enable-garbage-collector \\
                --enable-logs-handler \\
                --endpoint-reconciler-type=lease \\
                --etcd-cafile=/etc/etcd/ssl/etcd-root-ca.pem \\
                --etcd-certfile=/etc/etcd/ssl/etcd.pem \\
                --etcd-keyfile=/etc/etcd/ssl/etcd-key.pem \\
                --etcd-compaction-interval=0s \\
                --event-ttl=168h0m0s \\
                --kubelet-https=true \\
                --kubelet-certificate-authority=/etc/kubernetes/ssl/k8s-root-ca.pem \\
                --kubelet-client-certificate=/etc/kubernetes/ssl/kubelet-api-admin.pem \\
                --kubelet-client-key=/etc/kubernetes/ssl/kubelet-api-admin-key.pem \\
                --kubelet-timeout=3s \\
                --runtime-config=api/all=true \\
                --service-node-port-range=30000-50000 \\
                --service-account-key-file=/etc/kubernetes/ssl/k8s-root-ca.pem \\
                --tls-cert-file=/etc/kubernetes/ssl/kube-apiserver.pem \\
                --tls-private-key-file=/etc/kubernetes/ssl/kube-apiserver-key.pem \\
                --v=2"
EOFS6 

cat > controller-manager <<EOFS7
###
# The following values are used to configure the kubernetes controller-manager

# defaults from config and apiserver should be adequate

# Add your own!
KUBE_CONTROLLER_MANAGER_ARGS="  --address=127.0.0.1 \\
                                --authentication-kubeconfig=/etc/kubernetes/kube-controller-manager.kubeconfig \\
                                --authorization-kubeconfig=/etc/kubernetes/kube-controller-manager.kubeconfig \\
                                --bind-address=0.0.0.0 \\
                                --cluster-name=kubernetes \\
                                --cluster-signing-cert-file=/etc/kubernetes/ssl/k8s-root-ca.pem \\
                                --cluster-signing-key-file=/etc/kubernetes/ssl/k8s-root-ca-key.pem \\
                                --client-ca-file=/etc/kubernetes/ssl/k8s-root-ca.pem \\
                                --controllers=*,bootstrapsigner,tokencleaner \\
                                --deployment-controller-sync-period=10s \\
                                --experimental-cluster-signing-duration=87600h0m0s \\
                                --enable-garbage-collector=true \\
                                --kubeconfig=/etc/kubernetes/kube-controller-manager.kubeconfig \\
                                --leader-elect=true \\
                                --node-monitor-grace-period=20s \\
                                --node-monitor-period=5s \\
                                --port=10252 \\
                                --pod-eviction-timeout=2m0s \\
                                --requestheader-client-ca-file=/etc/kubernetes/ssl/k8s-root-ca.pem \\
                                --terminated-pod-gc-threshold=50 \\
                                --tls-cert-file=/etc/kubernetes/ssl/kube-controller-manager.pem \\
                                --tls-private-key-file=/etc/kubernetes/ssl/kube-controller-manager-key.pem \\
                                --root-ca-file=/etc/kubernetes/ssl/k8s-root-ca.pem \\
                                --secure-port=10257 \\
                                --service-cluster-ip-range=$service_cidr \\
                                --service-account-private-key-file=/etc/kubernetes/ssl/k8s-root-ca-key.pem \\
                                --use-service-account-credentials=true \\
                                --v=2
EOFS7

cat > scheduler <<EOFS8
###
# kubernetes scheduler config

# default config should be adequate

# Add your own!
KUBE_SCHEDULER_ARGS="   --address=127.0.0.1 \\
                        --authentication-kubeconfig=/etc/kubernetes/kube-scheduler.kubeconfig \\
                        --authorization-kubeconfig=/etc/kubernetes/kube-scheduler.kubeconfig \\
                        --bind-address=0.0.0.0 \\
                        --client-ca-file=/etc/kubernetes/ssl/k8s-root-ca.pem \\
                        --kubeconfig=/etc/kubernetes/kube-scheduler.kubeconfig \\
                        --requestheader-client-ca-file=/etc/kubernetes/ssl/k8s-root-ca.pem \\
                        --secure-port=10259 \\
                        --leader-elect=true \\
                        --port=10251 \\
                        --tls-cert-file=/etc/kubernetes/ssl/kube-scheduler.pem \\
                        --tls-private-key-file=/etc/kubernetes/ssl/kube-scheduler-key.pem \\
                        --v=2"
EOFS8 

cat > kubelet <<EOFS9
###
# kubernetes kubelet (minion) config

# The address for the info server to serve on (set to 0.0.0.0 or "" for all interfaces)
KUBELET_ADDRESS="--node-ip=\$node_ip"

# The port for the info server to serve on
# KUBELET_PORT="--port=10250"

# You may leave this blank to use the actual hostname
KUBELET_HOSTNAME="--hostname-override='\$node_hostname'"

# location of the api-server
# KUBELET_API_SERVER=""

# Add your own!
KUBELET_ARGS="  --address=0.0.0.0 \\
                --allow-privileged \\
                --anonymous-auth=false \\
                --authorization-mode=Webhook \\
                --bootstrap-kubeconfig=/etc/kubernetes/bootstrap.kubeconfig \\
                --client-ca-file=/etc/kubernetes/ssl/k8s-root-ca.pem \\
                --network-plugin=cni \\
                --cgroup-driver=cgroupfs \\
                --cert-dir=/etc/kubernetes/ssl \\
                --cluster-dns="$service_dns" \\
                --cluster-domain=cluster.local \\
                --cni-conf-dir=/etc/cni/net.d \\
                --eviction-soft=imagefs.available<15%,memory.available<512Mi,nodefs.available<15%,nodefs.inodesFree<10% \\
                --eviction-soft-grace-period=imagefs.available=3m,memory.available=1m,nodefs.available=3m,nodefs.inodesFree=1m \\
                --eviction-hard=imagefs.available<10%,memory.available<256Mi,nodefs.available<10%,nodefs.inodesFree<5% \\
                --eviction-max-pod-grace-period=30 \\
                --image-gc-high-threshold=80 \\
                --image-gc-low-threshold=70 \\
                --image-pull-progress-deadline=30s \\
                --kube-reserved=cpu=500m,memory=512Mi,ephemeral-storage=1Gi \\
                --kubeconfig=/etc/kubernetes/kubelet.kubeconfig \\
                --max-pods=100 \\
                --minimum-image-ttl-duration=720h0m0s \\
                --node-labels=node.kubernetes.io/k8s-node=true \\
                --pod-infra-container-image=mirrorgooglecontainers/pause-amd64:3.1 \\
                --port=10250 \\
                --read-only-port=0 \\
                --rotate-certificates \\
                --rotate-server-certificates \\
                --resolv-conf=/etc/resolv.conf \\
                --system-reserved=cpu=500m,memory=512Mi,ephemeral-storage=1Gi \\
                --fail-swap-on=false \\
                --v=2"
EOFS9
cat > proxy <<EOFS0
###
# kubernetes proxy config
# default config should be adequate
# Add your own!
KUBE_PROXY_ARGS="   --bind-address=0.0.0.0 \\
                    --cleanup-ipvs=true \\
                    --cluster-cidr=$service_cidr \\
                    --hostname-override=\$node_hostname \\
                    --healthz-bind-address=0.0.0.0 \\
                    --healthz-port=10256 \\
                    --masquerade-all=true \\
                    --proxy-mode=ipvs \\
                    --ipvs-min-sync-period=5s \\
                    --ipvs-sync-period=5s \\
                    --ipvs-scheduler=wrr \\
                    --kubeconfig=/etc/kubernetes/kube-proxy.kubeconfig \\
                    --logtostderr=true \\
                    --v=2"
EOFS0

#拷贝所有配置文件到指定的主机 

for i in ${master_nodes[*]} 
do 
   scp -r apiserver  controller-manager scheduler $i:/etc/kubernetes
   scp kube-apiserver.service kube-controller-manager.service  kube-scheduler.service  $i:/usr/lib/systemd/system
done


for i in ${all_nodes[*]}
do 
   scp -r ssl/* $i:/etc/kubernetes/ssl 
   scp kubelet proxy $i:/etc/kubernetes
   scp kubelet.service kube-proxy.service  $i:/usr/lib/systemd/system
   ssh $i 'systemctl daemon-reload;node_hostname=`hostname`;node_ip=$(grep `hostname` /etc/hosts|awk '{print $1}');sed 's/$node_hostname/'$node_hostname'/g' /etc/kubernetes/kubelet;sed 's/$node_ip/'$node_ip'/g' /etc/kubernetes/kubelet;sed 's/$node_hostname/'$node_hostname'/g' /etc/kubernetes/proxy;sed 's/$node_ip/'$node_ip'/g' /etc/kubernetes/apiserver;chown -R kube:kube /etc/kubernetes;'
   
done 

#nginx配置和安装【没有经过尝试不知道master节点上是否会自动监听127.0.0.1:6443端口，如果已经监听则nginx只需要在worker节点上，如果未监听则需要所有节点】

cat > nginx-proxy.service <<EOFG1
[Unit]
Description=kubernetes apiserver docker wrapper
Wants=docker.socket
After=docker.service

[Service]
User=root
PermissionsStartOnly=true
ExecStart=/usr/bin/docker run -p 127.0.0.1:6443:6443 \\
                              -v /etc/nginx:/etc/nginx \\
                              --name nginx-proxy \\
                              --net=host \\
                              --restart=on-failure:5 \\
                              --memory=512M \\
                              nginx:1.14.2-alpine
ExecStartPre=-/usr/bin/docker rm -f nginx-proxy
ExecStop=/usr/bin/docker stop nginx-proxy
Restart=always
RestartSec=15s
TimeoutStartSec=30s

[Install]
WantedBy=multi-user.target
EOFG1

cat > nginx.conf <<EOFG2
error_log stderr notice;

worker_processes auto;
events {
  	multi_accept on;
  	use epoll;
  	worker_connections 1024;
}

stream {
    upstream kube_apiserver {
        least_conn;
$(for i in ${master_nodes[*]}
do 
  echo "        server ""$i"":6443;"
done
)
    }

    server {
        listen        0.0.0.0:6443;
        proxy_pass    kube_apiserver;
        proxy_timeout 10m;
        proxy_connect_timeout 1s;
    }
}
EOFG2

#同步nginx服务到指定节点，并开始启动服务

for i in ${master_nodes[*]} 
do 
   ssh $i 'systemctl daemon-reload;systemctl restart kube-apiserver;systemctl restart kube-controller-manager;systemctl restart  kube-scheduler;systemctl restart  kube-proxy;'
   ssh $i 'systemctl enable kube-apiserver;systemctl enable kube-controller-manager;systemctl enable  kube-scheduler;systemctl enable  kubelet;systemctl enable  kube-proxy;'
done

for i in ${worker_nodes[*]} 
do  
   scp nginx.conf $i:/etc/nginx
   scp nginx-proxy.service $i:/usr/lib/systemd/system
   ssh $i 'systemctl daemon-reload;systemctl restart nginx-proxy && systemctl restart  kube-proxy;'
   ssh $i 'systemctl enable nginx-proxy;systemctl enable  kubelet;systemctl enable  kube-proxy;'
done

#手动为kubelet创建相关的用户账号信息【本机连接到k8s集群】
mkdir -p ~/.kube
cp admin.kubeconfig ~/.kube/config

# 创建用于 tls bootstrap 的 token secret
kubectl create -f bootstrap.secret.yaml

# 为了能让 kubelet 实现自动更新证书，需要配置相关 clusterrolebinding

# 允许 kubelet tls bootstrap 创建 csr 请求
kubectl create clusterrolebinding create-csrs-for-bootstrapping \
    --clusterrole=system:node-bootstrapper \
    --group=system:bootstrappers

# 自动批准 system:bootstrappers 组用户 TLS bootstrapping 首次申请证书的 CSR 请求
kubectl create clusterrolebinding auto-approve-csrs-for-group \
    --clusterrole=system:certificates.k8s.io:certificatesigningrequests:nodeclient \
    --group=system:bootstrappers

# 自动批准 system:nodes 组用户更新 kubelet 自身与 apiserver 通讯证书的 CSR 请求
kubectl create clusterrolebinding auto-approve-renewals-for-nodes \
    --clusterrole=system:certificates.k8s.io:certificatesigningrequests:selfnodeclient \
    --group=system:nodes

# 在 kubelet server 开启 api 认证的情况下，apiserver 反向访问 kubelet 10250 需要此授权(eg: kubectl logs)
kubectl create clusterrolebinding system:kubelet-api-admin \
    --clusterrole=system:kubelet-api-admin \
    --user=system:kubelet-api-admin

#启动所有主机上kubelet服务
for i in ${all_nodes[*]} 
do  
   ssh $i 'systemctl daemon-reload;systemctl restart kubelet;systemctl enable  kubelet;'
done

#查看已经签署kubelet发起的证书请求
kubectl certificate approve $(kubectl get csr|grep -i Pending|grep 'system:node'|awk '{print $1}')






