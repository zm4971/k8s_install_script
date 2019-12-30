#/bin/bash
#

master_host=()
worker_host=()

#init system 
#手动编写安装主机/etc/hosts文件以及进行内核升级
#rpm -Uvh http://www.elrepo.org/elrepo-release-7.0-2.el7.elrepo.noarch.rpm;rpm --import https://www.elrepo.org/RPM-GPG-KEY-elrepo.org;yum --disablerepo="*" --enablerepo="elrepo-kernel" list available;yum   --enablerepo="elrepo-kernel" install  kernel-lt -y 
#sed -i 's/GRUB_DEFAULT=saved/GRUB_DEFAULT=0/g' /etc/default/grub  && grub2-mkconfig -o /boot/grub2/grub.cfg

#ssh,hostnameset,hosts,firewalld,selinux,sysctl,time
#安装节点hosts文件手动编写

#安装节点内核文件修改
cat >> /etc/sysctl.conf << EOF
net.ipv4.ip_forward=1
net.bridge.bridge-nf-call-iptables=1
net.bridge.bridge-nf-call-ip6tables=1
vm.swappiness = 0
net.ipv4.tcp_tw_recycle=0
fs.inotify.max_user_instances=8192
fs.inotify.max_user_watches=1048576
fs.file-max=52706963
fs.nr_open=52706963
net.ipv6.conf.all.disable_ipv6=1
net.netfilter.nf_conntrack_max=2310720
net.ipv4.neigh.default.gc_thresh1=4096
net.ipv4.neigh.default.gc_thresh2=6144
net.ipv4.neigh.default.gc_thresh3=8194
EOF

#ssh等效性
	for i in `cat /etc/hosts|grep -i 'k8s' |awk '{print $1}'`;do ssh-copy-id $i;done  
#根据host文件设置对应主机主机名
   for i in `cat /etc/hosts|grep -i 'k8s' |awk '{print $1}'`;do scp /etc/hosts $i:/etc/hosts ;ssh $i "hostnamectl set-hostname `cat /etc/hosts|grep -i "$i"|awk '{print $2}'`;hostname";done 
#安装依赖软件
  for i in `cat /etc/hosts|grep -i 'k8s' |awk '{print $1}'`;do ssh $i 'yum install ntp wget conntrack ipset ipvsadm  -y';done 
#初始化配置 防火墙关闭，时间同步
	for i in `cat /etc/hosts|grep -i 'k8s' |awk '{print $1}'`;do ssh $i 'systemctl stop firewalld;systemctl disable firewalld;setenforce 0;sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config;ntpdate ntp1.aliyun.com; ln -sf /usr/share/zoneinfo/Asia/Shanghai  /etc/localtime  ';done 
#内核参数同步
   for i in `cat /etc/hosts|grep -i 'k8s' |awk '{print $1}'`;do scp /etc/sysctl.conf $i:/etc/sysctl.conf;ssh $i 'sysctl -p';done  
#ipvs相关参数配置
 cat > /etc/sysconfig/modules/ipvs.modules <<EOF1
#!/bin/bash
#

modprobe -- ip_vs
modprobe -- ip_vs_rr
modprobe -- ip_vs_wrr
modprobe -- ip_vs_sh
modprobe -- nf_conntrack_ipv4

EOF1
#所有主机同步ipvs设置
for i in `cat /etc/hosts|grep -i 'k8s' |awk '{print $1}'`;do scp /etc/sysconfig/modules/ipvs.modules $i:/etc/sysconfig/modules/ipvs.modules;ssh $i 'chmod +x /etc/sysconfig/modules/ipvs.modules;bash /etc/sysconfig/modules/ipvs.modules';done 

#安装docker-ce稳定版本
  for i in `cat /etc/hosts|grep -i 'k8s' |awk '{print $1}'`;do ssh $i "wget https://mirrors.aliyun.com/docker-ce/linux/centos/docker-ce.repo -O /etc/yum.repos.d/docker-ce.repo;yum --disablerepo='*' --enablerepo='docker-ce-stable' list available ;yum --enablerepo='docker-ce-stable' install docker-ce -y;systemctl start docker";done  

#编写本地docker配置文件
cat > /etc/docker/daemon.json <<EOF2
{
"max-concurrent-downloads": 5,
"registry-mirrors": ["https://7bezldxe.mirror.aliyuncs.com/","http://03afea1c.m.daocloud.io"],
"log-driver": "json-file",
"log-opts": {
    "max-size": "50m",
    "max-file": "3"
    }
}
<<EOF2
<<EOF2
#同步配置并重启docker
   for i in `cat /etc/hosts|grep -i 'k8s' |awk '{print $1}'`;do scp /etc/docker/daemon.json $i:/etc/docker/daemon.json;ssh $i 'systemctl restart docker;systemctl enable docker';done  

#最好每台主机都重启一次