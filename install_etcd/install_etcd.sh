#!/bin/bash 
#

#etcd_hosts=(192.168.0.11 192.168.0.12 192.168.0.13)
etcd_hosts=()
num=0

#证书请求文件
cat > etcd-root-ca-csr.json<<EOF
{
    "CN": "etcd-root-ca",
    "key": {
        "algo": "rsa",
        "size": 4096
    },
    "names": [
        {
            "O": "etcd",
            "OU": "etcd Security",
            "L": "Chengdu",
            "ST": "Sichuan",
            "C": "CN"
        }
    ],
    "ca": {
        "expiry": "87600h"
    }
}
EOF

cat > etcd-gencert.json <<EOF1
{
  "signing": {
    "default": {
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
EOF1

cat > etcd-csr.json << EOF2
{
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "O": "etcd",
            "OU": "etcd Security",
            "L": "Chengdu",
            "ST": "Sichuan",
            "C": "CN"
        }
    ],
    "CN": "etcd",
    "hosts": [
        "127.0.0.1",
        "localhost",
$(if [ ${#host[*]} -eq 0 ]
then
        echo "        *";
else
   while [ $num -lt "${#host[*]}" ]
   do
       n_num=$(($num+1))
     if [ "$n_num" -lt  "${#host[*]}" ]
     then
       echo "        ${host["$num"]},"
       num=$[$num+1];
     else
       echo "        ${host["$num"]}"
       break;
     fi
   done
fi)
    ]
}
EOF2

#下载命令文件
curl https://pkg.cfssl.org/R1.2/cfssl_linux-amd64 -o /usr/local/bin/cfssl
curl https://pkg.cfssl.org/R1.2/cfssljson_linux-amd64 -o /usr/local/bin/cfssljson
curl https://pkg.cfssl.org/R1.2/cfssl-certinfo_linux-amd64 -o /usr/local/bin/cfssl-certinfo

chmod +x /usr/local/bin/cfssl*

#生成证书文件
cfssl gencert --initca=true etcd-root-ca-csr.json | cfssljson --bare etcd-root-ca
cfssl gencert --ca etcd-root-ca.pem --ca-key etcd-root-ca-key.pem --config etcd-gencert.json etcd-csr.json | cfssljson --bare etcd 

mkdir -p ssl
mv *.pem ssl/
#本地下载二进制文件

set -e

ETCD_DEFAULT_VERSION="3.3.12"

if [ "$1" != "" ]; then
  ETCD_VERSION=$1
else
  echo -e "\033[33mWARNING: ETCD_VERSION is blank,use default version: ${ETCD_DEFAULT_VERSION}\033[0m"
  ETCD_VERSION=${ETCD_DEFAULT_VERSION}
fi

# 下载 Etcd 二进制文件
    if [ ! -f "etcd-v${ETCD_VERSION}-linux-amd64.tar.gz" ]; then
        wget https://github.com/coreos/etcd/releases/download/v${ETCD_VERSION}/etcd-v${ETCD_VERSION}-linux-amd64.tar.gz
        tar -zxvf etcd-v${ETCD_VERSION}-linux-amd64.tar.gz
    fi

#解压文件
tar -xvzf etcd-v${ETCD_VERSION}-linux-amd64.tar.gz 

#创建对应的配置文件

a_string=$(for j in ${etcd_hosts[*]}
do 
  i=`cat /etc/hosts|grep "$j"|awk '{print $2}'`
  echo "$i"="https://"$j":2380,"
done)

etcd_address=`echo $a_string | sed  's/ //g'|sed 's/.$//g'`
cat > etcd.conf << EOF3
# [member]
ETCD_NAME="\$node_hostname"
ETCD_DATA_DIR="/var/lib/etcd/data"
ETCD_WAL_DIR="/var/lib/etcd/wal"
ETCD_SNAPSHOT_COUNT="100"
ETCD_HEARTBEAT_INTERVAL="100"
ETCD_ELECTION_TIMEOUT="1000"
ETCD_LISTEN_PEER_URLS="https://"\$node_ip":2380"
ETCD_LISTEN_CLIENT_URLS="https://"\$node_ip":2379,http://127.0.0.1:2379"
ETCD_MAX_SNAPSHOTS="5"
ETCD_MAX_WALS="5"
#ETCD_CORS=""

# [cluster]
ETCD_INITIAL_ADVERTISE_PEER_URLS="https://"\$node_ip":2380"
# if you use different ETCD_NAME (e.g. test), set ETCD_INITIAL_CLUSTER value for this name, i.e. "test=http://..."
ETCD_INITIAL_CLUSTER="$etcd_address"
ETCD_INITIAL_CLUSTER_STATE="new"
ETCD_INITIAL_CLUSTER_TOKEN="etcd-cluster"
ETCD_ADVERTISE_CLIENT_URLS="https://"\$node_ip":2379"


# [security]
ETCD_CERT_FILE="/etc/etcd/ssl/etcd.pem"
ETCD_KEY_FILE="/etc/etcd/ssl/etcd-key.pem"
ETCD_CLIENT_CERT_AUTH="true"
ETCD_TRUSTED_CA_FILE="/etc/etcd/ssl/etcd-root-ca.pem"
ETCD_AUTO_TLS="true"
ETCD_PEER_CERT_FILE="/etc/etcd/ssl/etcd.pem"
ETCD_PEER_KEY_FILE="/etc/etcd/ssl/etcd-key.pem"
ETCD_PEER_CLIENT_CERT_AUTH="true"
ETCD_PEER_TRUSTED_CA_FILE="/etc/etcd/ssl/etcd-root-ca.pem"
ETCD_PEER_AUTO_TLS="true"
EOF3

cat >etcd.service <<EOF4
[Unit]
Description=Etcd Server
After=network.target
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
WorkingDirectory=/var/lib/etcd/
EnvironmentFile=-/etc/etcd/etcd.conf
User=etcd
# set GOMAXPROCS to number of processors
ExecStart=/bin/bash -c "GOMAXPROCS=$(nproc) /usr/local/bin/etcd --name=\"${ETCD_NAME}\" --data-dir=\"${ETCD_DATA_DIR}\" --listen-client-urls=\"${ETCD_LISTEN_CLIENT_URLS}\""
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF4

#etcd主机创建相关的用户以及目录
for i in ${etcd_hosts[*]}
do 
   ssh $i "useradd etcd -s /sbin/nologin;mkdir -p /var/lib/etcd;mkdir -p /etc/etcd/ssl;chown -R etcd:etcd /etc/etcd;chmod  -R 755 /etc/etcd/ssl;chown -R etcd:etcd /var/lib/etcd"    
done 

#拷贝配置文件以及替换配置文件
for i in ${etcd_hosts[*]}
do 
  scp etcd.conf $i:/etc/etcd/
  scp -r ssl/* $i:/etc/etcd/ssl/
  scp etcd.service $i:/usr/lib/systemd/system/
  scp -r etcd-v${ETCD_VERSION}-linux-amd64/etcd* $i:/usr/local/bin/
  ssh $i "node_hostname=`hostname`;node_ip=$(grep `hostname` /etc/hosts|awk '{print $1}');sed 's/$node_hostname/'$node_hostname'/g' /etc/etcd/etcd.conf;sed 's/$node_ip/'$node_ip'/g' /etc/etcd/etcd.conf  "
  ssh $i "chown -R etcd:etcd /etc/etcd;chmod +x /usr/local/bin/*;systemctl daemon-reload;systemctl enable etcd"
done
