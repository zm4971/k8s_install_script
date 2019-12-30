#!/bin/bash
#

#安装网络插件calico 
cat > calico.yaml << EOFG3
---
# Source: calico/templates/calico-etcd-secrets.yaml
# The following contains k8s Secrets for use with a TLS enabled etcd cluster.
# For information on populating Secrets, see http://kubernetes.io/docs/user-guide/secrets/
apiVersion: v1
kind: Secret
type: Opaque
metadata:
  name: calico-etcd-secrets
  namespace: kube-system
data:
  # Populate the following with etcd TLS configuration if desired, but leave blank if
  # not using TLS for etcd.
  # The keys below should be uncommented and the values populated with the base64
  # encoded contents of each file that would be associated with the TLS data.
  # Example command for encoding a file contents: cat <file> | base64 -w 0
  etcd-cert: `cat /etc/etcd/ssl/etcd.pem | base64 | tr -d '\n'`
  etcd-key: `cat /etc/etcd/ssl/etcd-key.pem | base64 | tr -d '\n'`
  etcd-ca: `cat /etc/etcd/ssl/etcd-root-ca.pem | base64 | tr -d '\n'`
#  etcd-key: LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFb3dJQkFBS0NBUUVBdGtOVlV5QWtOOWxDKy9EbzlCRkt0em5IZlFJKzJMK2crclkwLzNoOExJTEFoWUtXCm1XdVNNQUFjbyt4clVtaTFlUGIzcmRKR0p1NEhmRXFmalYvakhvN0haOGxteXd0S29Ed254aU9jZDRlRXltcXEKTEFVYzZ5RWU4dXFGZ2pLVHE4SjV2Z1F1cGp0ZlZnZXRPdVVsWWtWbUNKMWtpUW0yVk5WRnRWZ0Fqck1xSy9POApJTXN6RWRYU3BDc1Zwb0kzaUpoVHJSRng4ZzRXc2hwNG1XMzhMWDVJYVVoMWZaSGVMWm1sRURpclBWMGRTNmFWCmJscUk2aUFwanVBc3hYWjFlVTdmOVZWK01PVmNVc3A4cDAxNmJzS3R6VTJGSnB6ZlM3c1BlbGpKZGgzZmVOdk8KRVl1aDlsU0c1VGNKUHBuTTZ0R0ppaHpEWCt4dnNGa3d5MVJSVlFJREFRQUJBb0lCQUYwRXVqd2xVRGFzakJJVwpubDFKb2U4bTd0ZXUyTEk0QW9sUmluVERZZVE1aXRYWWt0R1Q0OVRaaWNSak9WYWlsOU0zZjZwWGdYUUcwUTB1CjdJVHpaZTlIZ1I5SDIwMU80dlFxSDBaeEVENjBqQ0hlRkNGSkxyd1ZlRDBUVWJYajZCZWx0Z296Q2pmT1gxYUIKcm5nN1VEdjZIUnZTYitlOGJEQ1pjKzBjRDVURG4vUWV0R1dtUmpJZ1FhMmlUT2MzSzFiaHo2RTl5Nk9qWkFTMQpiai9NL1dOd20yNHRxQTJEeWdjcGVmUGFnTWtFNm9uYXBFVHhZdi83QmNqcUhtdVd6WE1wMzd6VGpPckwxVDdmClhrbHdFMUYrMDRhRDR6dDZycEdmN0lqSUdvRkEvT2ZrRGZiYkRjN2NsaDJ1SkNMTVE5MGpuSkxMTGRSV3dQRW4KMkkyY3IvVUNnWUVBN3BjT29VV3RwdDJjWGIzSnl3Tkh4aXl1bEc4V1JENjBlQ1MrUXFnQUZndU5JWFJlMEREUwovSWY0M1BhaVB3TjhBS216ZTRKbGsxM3Rnd29qdi9RWVFVblJzZi9PbnpUUlFoWVJXT2lxSE5lSmFvOUxFU0VDClcxNXNmUjhnYzd0dFdPZ0loZkhudmdCR0QvYmUzS1NWVjdUY0lndVVjV3RzeHhLdjZ4LzJNdHNDZ1lFQXc1QVIKWk9HNUp4UGVNV3FVRUR3QjJuQmt6WEtGblpNSEJXV2FOeHpEaTI0NmZEVWM2T1hSTTJJanh2cmVkc3JKQjBXMwovelNDeFdUbkRmL3RJY1lKMjRuTmNsMUNDS2hTNVE5bVZxanZ3dE1SaEF1Uk5VSFJSVjZLNS91V1hHQzAzekR3CkEvMUFSd3lZSHNHTlJVOFRNNnpNRFcxL0x5djZNZ2pnOFBIamk0OENnWUVBa3JwelZOcjFJRm5KZ0J6bnJPSW4Ka2NpSTFPQThZVnZ1d0xSWURjWWp4MnJ6TUUvUXYxaEhhT1oyTmUyM2VlazZxVzJ6NDVFZHhyTk5EZmwrWXQ1Swp6RndKaWQ0M3c5RkhuOHpTZmtzWDB3VDZqWDN5UEdhQWZKQmxSODJNdDUvY2I0RERQUnkzMkRGeTVQNTlzRlBIClJGa0Z5Q28yOEVtUWJCMGg4d2VFOFdFQ2dZQm1IeUptS3RWVUNiVDYyeXZzZWxtQlp6WE1ieVJGRDlVWHhXSE4KcTlDVlMvOXdndy9Rc3NvVzZnWEN6NWhDTWt6ZDVsTmFDbUxMajVCMHFCTjlrbnZ0VDcyZ0hnRHdvbTEvUGhaego1STRuajY3UzVITjBleVU3ODAzWUxISHRWWGErSWtFRDVFaWZrWDBTZW9JNkVqdjF2U05sVTZ1WngzNUVpSXhtClpmb3NFd0tCZ0dQMmpsK0lPcFV5Y2NEL25EbUJWa05CWHoydWhncU8yYjE4d0hSOGdiSXoyVTRBZnpreXVkWUcKZzQvRjJZZVdCSEdNeTc5N0I2c0hjQTdQUWNNdUFuRk11MG9UNkMvanpDSHpoK2VaaS8wdHJRTHJGeWFFaGVuWgpnazduUTdHNHhROWZLZmVTeFcyUlNNUUR0MTZULzNOTitTOEZCTjJmZEliY3V4QWs0WjVHCi0tLS0tRU5EIFJTQSBQUklWQVRFIEtFWS0tLS0tCg==
#  etcd-cert: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUZFekNDQXZ1Z0F3SUJBZ0lVRGJqcTdVc2ViY2toZXRZb1RPNnRsc1N1c1k0d0RRWUpLb1pJaHZjTkFRRU4KQlFBd2J6RUxNQWtHQTFVRUJoTUNRMDR4RURBT0JnTlZCQWdUQjBKbGFXcHBibWN4RURBT0JnTlZCQWNUQjBKbAphV3BwYm1jeERUQUxCZ05WQkFvVEJHVjBZMlF4RmpBVUJnTlZCQXNURFdWMFkyUWdVMlZqZFhKcGRIa3hGVEFUCkJnTlZCQU1UREdWMFkyUXRjbTl2ZEMxallUQWVGdzB4T1RBek1UWXdNelV4TURCYUZ3MHlPVEF6TVRNd016VXgKTURCYU1HY3hDekFKQmdOVkJBWVRBa05PTVJBd0RnWURWUVFJRXdkQ1pXbHFhVzVuTVJBd0RnWURWUVFIRXdkQwpaV2xxYVc1bk1RMHdDd1lEVlFRS0V3UmxkR05rTVJZd0ZBWURWUVFMRXcxbGRHTmtJRk5sWTNWeWFYUjVNUTB3CkN3WURWUVFERXdSbGRHTmtNSUlCSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDQVFFQXRrTlYKVXlBa045bEMrL0RvOUJGS3R6bkhmUUkrMkwrZytyWTAvM2g4TElMQWhZS1dtV3VTTUFBY28reHJVbWkxZVBiMwpyZEpHSnU0SGZFcWZqVi9qSG83SFo4bG15d3RLb0R3bnhpT2NkNGVFeW1xcUxBVWM2eUVlOHVxRmdqS1RxOEo1CnZnUXVwanRmVmdldE91VWxZa1ZtQ0oxa2lRbTJWTlZGdFZnQWpyTXFLL084SU1zekVkWFNwQ3NWcG9JM2lKaFQKclJGeDhnNFdzaHA0bVczOExYNUlhVWgxZlpIZUxabWxFRGlyUFYwZFM2YVZibHFJNmlBcGp1QXN4WFoxZVU3Zgo5VlYrTU9WY1VzcDhwMDE2YnNLdHpVMkZKcHpmUzdzUGVsakpkaDNmZU52T0VZdWg5bFNHNVRjSlBwbk02dEdKCmloekRYK3h2c0Zrd3kxUlJWUUlEQVFBQm80R3VNSUdyTUE0R0ExVWREd0VCL3dRRUF3SUZvREFkQmdOVkhTVUUKRmpBVUJnZ3JCZ0VGQlFjREFRWUlLd1lCQlFVSEF3SXdEQVlEVlIwVEFRSC9CQUl3QURBZEJnTlZIUTRFRmdRVQpFKzVsWWN1LzhieHJ2WjNvUnRSMmEvOVBJRkF3SHdZRFZSMGpCQmd3Rm9BVTJaVWM3R2hGaG1PQXhzRlZ3VEEyCm5lZFJIdmN3TEFZRFZSMFJCQ1V3STRJSmJHOWpZV3hvYjNOMGh3Ui9BQUFCaHdUQXFBRXpod1RBcUFFMGh3VEEKcUFFMU1BMEdDU3FHU0liM0RRRUJEUVVBQTRJQ0FRQUx3Vkc2QW93cklwZzQvYlRwWndWL0pBUWNLSnJGdm52VApabDVDdzIzNDI4UzJLLzIwaXphaStEWUR1SXIwQ0ZCa2xGOXVsK05ROXZMZ1lqcE0rOTNOY3I0dXhUTVZsRUdZCjloc3NyT1FZZVBGUHhBS1k3RGd0K2RWUGwrWlg4MXNWRzJkU3ZBbm9Kd3dEVWt5U0VUY0g5NkszSlNKS2dXZGsKaTYxN21GYnMrTlcxdngrL0JNN2pVU3ZRUzhRb3JGQVE3SlcwYzZ3R2V4RFEzZExvTXJuR3Vocjd0V0E0WjhwawpPaE12cWdhWUZYSThNUm4yemlLV0R6QXNsa0hGd1RZdWhCNURMSEt0RUVwcWhxbGh1RThwTkZMaVVSV2xQWWhlCmpDNnVKZ0hBZDltcSswd2pyTmxqKzlWaDJoZUJWNldXZEROVTZaR2tpR003RW9YbDM1OWdUTzJPUkNLUk5vZ0YKRVplR25HcjJQNDhKbnZjTnFmZzNPdUtYd24wRDVYYllSWjFuYnR5WG9mMFByUUhEU21wUFVPMWNiZUJjSWVtcQpEVWozK0MrRzBRS1FLQlZDTXJzNXJIVlVWVkJZZzk5ZW1sRE1zUE5TZm9JWDQwTVFCeTdKMnpxRVV5M0sxcGlaCkhwT0lZT1RrWDRhczhqcGYxMnkxSXoxRVZydE1xek83d294VmMwdHRZYWN5NzUrVzZuS1hlWjBaand5aTVYSzUKZGduSVhmZW51RUNlWFNDdWZCSmUxVklzaXVWZ3cyRjlUNk5zRDhnQ3A5SlhTamJ1SXpiM3ArNU9uZzM2ZnBRdQpXZVBCY0dQVXE5cGEwZUtOUGJXNjlDUHdtUTQ2cjg0T3hTTURHWC9CMElqNUtNUnZUMmhPUXBqTVpSblc5OUxFCjRMbUJuUTg1Wmc9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==
#  etcd-ca: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUZyakNDQTVhZ0F3SUJBZ0lVWXVIKzIxYlNaU2hncVYxWkx3a2o4RmpZbUl3d0RRWUpLb1pJaHZjTkFRRU4KQlFBd2J6RUxNQWtHQTFVRUJoTUNRMDR4RURBT0JnTlZCQWdUQjBKbGFXcHBibWN4RURBT0JnTlZCQWNUQjBKbAphV3BwYm1jeERUQUxCZ05WQkFvVEJHVjBZMlF4RmpBVUJnTlZCQXNURFdWMFkyUWdVMlZqZFhKcGRIa3hGVEFUCkJnTlZCQU1UREdWMFkyUXRjbTl2ZEMxallUQWVGdzB4T1RBek1UWXdNelV4TURCYUZ3MHlPVEF6TVRNd016VXgKTURCYU1HOHhDekFKQmdOVkJBWVRBa05PTVJBd0RnWURWUVFJRXdkQ1pXbHFhVzVuTVJBd0RnWURWUVFIRXdkQwpaV2xxYVc1bk1RMHdDd1lEVlFRS0V3UmxkR05rTVJZd0ZBWURWUVFMRXcxbGRHTmtJRk5sWTNWeWFYUjVNUlV3CkV3WURWUVFERXd4bGRHTmtMWEp2YjNRdFkyRXdnZ0lpTUEwR0NTcUdTSWIzRFFFQkFRVUFBNElDRHdBd2dnSUsKQW9JQ0FRRGFLK0s4WStqZkdOY2pOeUloeUhXSE5adWxVZzVKZFpOVU9GOHFXbXJMa0NuY2ZWdVF3dmI4cDFwLwpSSjBFOWo0OFBhZ1RJT3U2TU81R24zejFrZGpHRk9jOVZwMlZjYWJEQzJLWWJvRzdVQ0RmTWkzR1MzUnhUejVkCnh0MG1Ya2liVkMvc01NU2RrRm1mU2FCSXBoKzAyTnMwZURyMzNtUWxTdURlTWozNHJaTkVwMzRnUUk0eElTejAKbXhXR0dWNzcwUE9ScVgrZUthTEpiclp3anFFcnpHMEtEVUlBM0ZuTFdRMnp4b0VwN3JZby9LaGRiOHdETE1kbQp6VXNOZHI0T1F4MFBVRXA4akRUU2lFODkydDQ4KytsOHJ0MW4vTHFRc1FhVncrQlQrMTRvRHdIVkFaRXZ2ZnMwCmZkZ0QvU2RINGJRdHNhT21BdFByQldseU5aMUxIZkR2djMraXFzNk83UXpWUTFCK1c5cFRxdUZ2YUxWN3R1S3UKSXNlUFlseFdjV2E2M0hGbFkxVVJ6M0owaGtrZEZ1dkhUc0dhZDVpaWVrb0dUcFdTN2dVdCtTeWVJT2FhMldHLwp4Y1NiUWE0Y2xiZThuUHV2c1ZFVDhqZ0d0NGVLT25yRVJId0hMb2VleEpsSjdUdnhHNHpOTHZsc2FOL29iRzFDClUzMXczZ2d1SXpzRk5yallsUFdSZ0hSdXdPTlE5anlkM2dqVmNYUFdHTFJISUdYbjNhUDluT3A0OE9WWDhzbXoKOGIwS0V4UVpEQWUyS0tjWEg5a1ZiUFJQSWlLeGpXelV5aDMzQlRNejlPczZHcWM0Zk05c1hxbGRhVzBGd3g4MQpJaklScWx5a3VOSXNDWGhMUzhlNmVtdUNYMTVDZGNKb0ZmdXRuTENvV1B4Umg5OEF4UUlEQVFBQm8wSXdRREFPCkJnTlZIUThCQWY4RUJBTUNBUVl3RHdZRFZSMFRBUUgvQkFVd0F3RUIvekFkQmdOVkhRNEVGZ1FVMlpVYzdHaEYKaG1PQXhzRlZ3VEEybmVkUkh2Y3dEUVlKS29aSWh2Y05BUUVOQlFBRGdnSUJBSjh3bVNJMVBsQm8zcE1RWC9DOQpRS1RrR0xvVUhGdWprdFoxM1FYeXQ1LzFSeVB2WG1lLy90N3FHR2I5RmJZSm9BYTRTd3JSZkYzZmh3UDZaS0FnCnNYSEliR2gwc014UTdqVmQwMUNMWkoxQmZFNGZtTVlaQUlEWGpTcTNqbHJXZWcxL2hWTFN2dXRuUEFWSXc1SWwKZUdXRTMyOVJ2b2d2dXV6dUsxY2xwZFpIL2p3UlZjUUFUK0xvT2xFZ3Rkd293c0xpaWx3WE95eEZLZDd1UDk3bgozTFZUekFNN3Flell4SUVMQVlUUUN5eTdpeEIxNXlJV1UrUWhreUFtWXJoNEN6VUNNUjQreDlpaGZ6UnlOQkxLCmRBRTdwcjdyUEM4WFQ0YWh2SkJCZTg1THViTVdVRmprcEF5cklQODYyYkFCOCtKSXNFdXNZVGdQakUrMGhteTkKT0NIU2x4Q25GQVdPUXcwQ05Kb3AxWGpHU0RZOXlXL1NNWS83T3B0QlBhT3VWTzVwZTg3VmVXRFFtYmlpdnc3MQo4cFhDQnN6ZWNsdjJZKzdscTRnL0FaQkViVXRvLzV4UXJCbmZGKy9hZFFOQzY4aG4yYzZWa3czYTVDR0ZMN0p2CjhWdFNmeFEzZnFUci9TdzlJbkVKVWpuc0Y3R0xINzZMWXZIU05WeldhMkhiVFNlTnQ0RUlpdlEwb2d0b2hzY0kKSHlrZlpRQ3Z6ZnBSZi9TODFiRDNnU29jQ3NzR2crdVpVU0FMdVhBRDE4RkRXNzg2LzRCckcrMzVLOVBLNktUZwpoWGN4WmRHd3V1RWx0aTRBNWx4OHNrZExPSkZ6TUJPWFJNU2Jsc0dna3pGK2JNRkMrMHV3WW1WK0VTRUdwdy9NCm93WUN1dHh2a3ltL2NOcEk1bjFhanpEcQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==
---
# Source: calico/templates/calico-config.yaml
# This ConfigMap is used to configure a self-hosted Calico installation.
kind: ConfigMap
apiVersion: v1
metadata:
  name: calico-config
  namespace: kube-system
data:
  # Configure this with the location of your etcd cluster.
  etcd_endpoints: "$etcd_address"

  # If you're using TLS enabled etcd uncomment the following.
  # You must also populate the Secret below with these files.
  etcd_ca: "/calico-secrets/etcd-ca"
  etcd_cert: "/calico-secrets/etcd-cert"
  etcd_key: "/calico-secrets/etcd-key"
  # Typha is disabled.
  typha_service_name: "none"
  # Configure the Calico backend to use.
  calico_backend: "bird"

  # Configure the MTU to use
  veth_mtu: "1440"

  # The CNI network configuration to install on each node.  The special
  # values in this config will be automatically populated.
  cni_network_config: |-
    {
      "name": "k8s-pod-network",
      "cniVersion": "0.3.0",
      "plugins": [
        {
          "type": "calico",
          "log_level": "info",
          "etcd_endpoints": "__ETCD_ENDPOINTS__",
          "etcd_key_file": "__ETCD_KEY_FILE__",
          "etcd_cert_file": "__ETCD_CERT_FILE__",
          "etcd_ca_cert_file": "__ETCD_CA_CERT_FILE__",
          "mtu": __CNI_MTU__,
          "ipam": {
              "type": "calico-ipam"
          },
          "policy": {
              "type": "k8s"
          },
          "kubernetes": {
              "kubeconfig": "__KUBECONFIG_FILEPATH__"
          }
        },
        {
          "type": "portmap",
          "snat": true,
          "capabilities": {"portMappings": true}
        }
      ]
    }

---
# Source: calico/templates/rbac.yaml

# Include a clusterrole for the kube-controllers component,
# and bind it to the calico-kube-controllers serviceaccount.
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1beta1
metadata:
  name: calico-kube-controllers
rules:
  # Pods are monitored for changing labels.
  # The node controller monitors Kubernetes nodes.
  # Namespace and serviceaccount labels are used for policy.
  - apiGroups: [""]
    resources:
      - pods
      - nodes
      - namespaces
      - serviceaccounts
    verbs:
      - watch
      - list
  # Watch for changes to Kubernetes NetworkPolicies.
  - apiGroups: ["networking.k8s.io"]
    resources:
      - networkpolicies
    verbs:
      - watch
      - list
---
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1beta1
metadata:
  name: calico-kube-controllers
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: calico-kube-controllers
subjects:
- kind: ServiceAccount
  name: calico-kube-controllers
  namespace: kube-system
---
# Include a clusterrole for the calico-node DaemonSet,
# and bind it to the calico-node serviceaccount.
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1beta1
metadata:
  name: calico-node
rules:
  # The CNI plugin needs to get pods, nodes, and namespaces.
  - apiGroups: [""]
    resources:
      - pods
      - nodes
      - namespaces
    verbs:
      - get
  - apiGroups: [""]
    resources:
      - endpoints
      - services
    verbs:
      # Used to discover service IPs for advertisement.
      - watch
      - list
  - apiGroups: [""]
    resources:
      - nodes/status
    verbs:
      # Needed for clearing NodeNetworkUnavailable flag.
      - patch
---
apiVersion: rbac.authorization.k8s.io/v1beta1
kind: ClusterRoleBinding
metadata:
  name: calico-node
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: calico-node
subjects:
- kind: ServiceAccount
  name: calico-node
  namespace: kube-system
---

---
# Source: calico/templates/calico-node.yaml
# This manifest installs the calico/node container, as well
# as the Calico CNI plugins and network config on
# each master and worker node in a Kubernetes cluster.
kind: DaemonSet
apiVersion: extensions/v1beta1
metadata:
  name: calico-node
  namespace: kube-system
  labels:
    k8s-app: calico-node
spec:
  selector:
    matchLabels:
      k8s-app: calico-node
  updateStrategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 1
  template:
    metadata:
      labels:
        k8s-app: calico-node
      annotations:
        # This, along with the CriticalAddonsOnly toleration below,
        # marks the pod as a critical add-on, ensuring it gets
        # priority scheduling and that its resources are reserved
        # if it ever gets evicted.
        scheduler.alpha.kubernetes.io/critical-pod: ''
    spec:
      nodeSelector:
        beta.kubernetes.io/os: linux
      hostNetwork: true
      tolerations:
        # Make sure calico-node gets scheduled on all nodes.
        - effect: NoSchedule
          operator: Exists
        # Mark the pod as a critical add-on for rescheduling.
        - key: CriticalAddonsOnly
          operator: Exists
        - effect: NoExecute
          operator: Exists
      serviceAccountName: calico-node
      # Minimize downtime during a rolling upgrade or deletion; tell Kubernetes to do a "force
      # deletion": https://kubernetes.io/docs/concepts/workloads/pods/pod/#termination-of-pods.
      terminationGracePeriodSeconds: 0
      initContainers:
        # This container installs the Calico CNI binaries
        # and CNI network config file on each node.
        - name: install-cni
          image: calico/cni:v3.6.0
          command: ["/install-cni.sh"]
          env:
            # Name of the CNI config file to create.
            - name: CNI_CONF_NAME
              value: "10-calico.conflist"
            # The CNI network config to install on each node.
            - name: CNI_NETWORK_CONFIG
              valueFrom:
                configMapKeyRef:
                  name: calico-config
                  key: cni_network_config
            # The location of the Calico etcd cluster.
            - name: ETCD_ENDPOINTS
              valueFrom:
                configMapKeyRef:
                  name: calico-config
                  key: etcd_endpoints
            # CNI MTU Config variable
            - name: CNI_MTU
              valueFrom:
                configMapKeyRef:
                  name: calico-config
                  key: veth_mtu
            # Prevents the container from sleeping forever.
            - name: SLEEP
              value: "false"
          volumeMounts:
            - mountPath: /host/opt/cni/bin
              name: cni-bin-dir
            - mountPath: /host/etc/cni/net.d
              name: cni-net-dir
            - mountPath: /calico-secrets
              name: etcd-certs
      containers:
        # Runs calico/node container on each Kubernetes node.  This
        # container programs network policy and routes on each
        # host.
        - name: calico-node
          image: calico/node:v3.6.0
          env:
            # The location of the Calico etcd cluster.
            - name: ETCD_ENDPOINTS
              valueFrom:
                configMapKeyRef:
                  name: calico-config
                  key: etcd_endpoints
            # Location of the CA certificate for etcd.
            - name: ETCD_CA_CERT_FILE
              valueFrom:
                configMapKeyRef:
                  name: calico-config
                  key: etcd_ca
            # Location of the client key for etcd.
            - name: ETCD_KEY_FILE
              valueFrom:
                configMapKeyRef:
                  name: calico-config
                  key: etcd_key
            # Location of the client certificate for etcd.
            - name: ETCD_CERT_FILE
              valueFrom:
                configMapKeyRef:
                  name: calico-config
                  key: etcd_cert
            # Set noderef for node controller.
            - name: CALICO_K8S_NODE_REF
              valueFrom:
                fieldRef:
                  fieldPath: spec.nodeName
            # Choose the backend to use.
            - name: CALICO_NETWORKING_BACKEND
              valueFrom:
                configMapKeyRef:
                  name: calico-config
                  key: calico_backend
            # Cluster type to identify the deployment type
            - name: CLUSTER_TYPE
              value: "k8s,bgp"
            # Auto-detect the BGP IP address.
            - name: IP
              value: "autodetect"
            # Enable IPIP
            - name: CALICO_IPV4POOL_IPIP
              value: "Always"
            # Set MTU for tunnel device used if ipip is enabled
            - name: FELIX_IPINIPMTU
              valueFrom:
                configMapKeyRef:
                  name: calico-config
                  key: veth_mtu
            # The default IPv4 pool to create on startup if none exists. Pod IPs will be
            # chosen from this range. Changing this value after installation will have
            # no effect. This should fall within `--cluster-cidr`.
            - name: CALICO_IPV4POOL_CIDR
              value: "10.20.0.0/16"
            # Disable file logging so `kubectl logs` works.
            - name: CALICO_DISABLE_FILE_LOGGING
              value: "true"
            # Set Felix endpoint to host default action to ACCEPT.
            - name: FELIX_DEFAULTENDPOINTTOHOSTACTION
              value: "ACCEPT"
            # Disable IPv6 on Kubernetes.
            - name: FELIX_IPV6SUPPORT
              value: "false"
            # Set Felix logging to "info"
            - name: FELIX_LOGSEVERITYSCREEN
              value: "info"
            - name: FELIX_HEALTHENABLED
              value: "true"
            - name: IP_AUTODETECTION_METHOD
              value: can-reach=$( ip route |grep -i default |awk '{print $3}')
          securityContext:
            privileged: true
          resources:
            requests:
              cpu: 250m
          livenessProbe:
            httpGet:
              path: /liveness
              port: 9099
              host: localhost
            periodSeconds: 10
            initialDelaySeconds: 10
            failureThreshold: 6
          readinessProbe:
            exec:
              command:
              - /bin/calico-node
              - -bird-ready
              - -felix-ready
            periodSeconds: 10
          volumeMounts:
            - mountPath: /lib/modules
              name: lib-modules
              readOnly: true
            - mountPath: /run/xtables.lock
              name: xtables-lock
              readOnly: false
            - mountPath: /var/run/calico
              name: var-run-calico
              readOnly: false
            - mountPath: /var/lib/calico
              name: var-lib-calico
              readOnly: false
            - mountPath: /calico-secrets
              name: etcd-certs
      volumes:
        # Used by calico/node.
        - name: lib-modules
          hostPath:
            path: /lib/modules
        - name: var-run-calico
          hostPath:
            path: /var/run/calico
        - name: var-lib-calico
          hostPath:
            path: /var/lib/calico
        - name: xtables-lock
          hostPath:
            path: /run/xtables.lock
            type: FileOrCreate
        # Used to install CNI.
        - name: cni-bin-dir
          hostPath:
            path: /opt/cni/bin
        - name: cni-net-dir
          hostPath:
            path: /etc/cni/net.d
        # Mount in the etcd TLS secrets with mode 400.
        # See https://kubernetes.io/docs/concepts/configuration/secret/
        - name: etcd-certs
          secret:
            secretName: calico-etcd-secrets
            defaultMode: 0400
---

apiVersion: v1
kind: ServiceAccount
metadata:
  name: calico-node
  namespace: kube-system

---
# Source: calico/templates/calico-kube-controllers.yaml
# This manifest deploys the Calico Kubernetes controllers.
# See https://github.com/projectcalico/kube-controllers
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: calico-kube-controllers
  namespace: kube-system
  labels:
    k8s-app: calico-kube-controllers
  annotations:
    scheduler.alpha.kubernetes.io/critical-pod: ''
spec:
  # The controllers can only have a single active instance.
  replicas: 1
  strategy:
    type: Recreate
  template:
    metadata:
      name: calico-kube-controllers
      namespace: kube-system
      labels:
        k8s-app: calico-kube-controllers
    spec:
      nodeSelector:
        beta.kubernetes.io/os: linux
      # The controllers must run in the host network namespace so that
      # it isn't governed by policy that would prevent it from working.
      hostNetwork: true
      tolerations:
        # Mark the pod as a critical add-on for rescheduling.
        - key: CriticalAddonsOnly
          operator: Exists
        - effect: NoSchedule
          operator: Exists
        - key: node-role.kubernetes.io/master
          effect: NoSchedule
      serviceAccountName: calico-kube-controllers
      containers:
        - name: calico-kube-controllers
          image: calico/kube-controllers:v3.6.0
          env:
            # The location of the Calico etcd cluster.
            - name: ETCD_ENDPOINTS
              valueFrom:
                configMapKeyRef:
                  name: calico-config
                  key: etcd_endpoints
            # Location of the CA certificate for etcd.
            - name: ETCD_CA_CERT_FILE
              valueFrom:
                configMapKeyRef:
                  name: calico-config
                  key: etcd_ca
            # Location of the client key for etcd.
            - name: ETCD_KEY_FILE
              valueFrom:
                configMapKeyRef:
                  name: calico-config
                  key: etcd_key
            # Location of the client certificate for etcd.
            - name: ETCD_CERT_FILE
              valueFrom:
                configMapKeyRef:
                  name: calico-config
                  key: etcd_cert
            # Choose which controllers to run.
            - name: ENABLED_CONTROLLERS
              value: policy,namespace,serviceaccount,workloadendpoint,node
          volumeMounts:
            # Mount in the etcd TLS secrets.
            - mountPath: /calico-secrets
              name: etcd-certs
          readinessProbe:
            exec:
              command:
              - /usr/bin/check-status
              - -r
      volumes:
        # Mount in the etcd TLS secrets with mode 400.
        # See https://kubernetes.io/docs/concepts/configuration/secret/
        - name: etcd-certs
          secret:
            secretName: calico-etcd-secrets
            defaultMode: 0400

---

apiVersion: v1
kind: ServiceAccount
metadata:
  name: calico-kube-controllers
  namespace: kube-system
EOFG3

#部署coredns 

cat > coredns.yaml << EOFG4
apiVersion: v1
kind: ServiceAccount
metadata:
  name: coredns
  namespace: kube-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  labels:
    kubernetes.io/bootstrapping: rbac-defaults
  name: system:coredns
rules:
- apiGroups:
  - ""
  resources:
  - endpoints
  - services
  - pods
  - namespaces
  verbs:
  - list
  - watch
- apiGroups:
  - ""
  resources:
  - nodes
  verbs:
  - get
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  annotations:
    rbac.authorization.kubernetes.io/autoupdate: "true"
  labels:
    kubernetes.io/bootstrapping: rbac-defaults
  name: system:coredns
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:coredns
subjects:
- kind: ServiceAccount
  name: coredns
  namespace: kube-system
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: coredns
  namespace: kube-system
data:
  Corefile: |
    .:53 {
        errors
        health
        kubernetes cluster.local in-addr.arpa ip6.arpa {
          pods insecure
          upstream
          fallthrough in-addr.arpa ip6.arpa
        }
        prometheus :9153
        forward . /etc/resolv.conf
        cache 30
        loop
        reload
        loadbalance
    }
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: coredns
  namespace: kube-system
  labels:
    k8s-app: kube-dns
    kubernetes.io/name: "CoreDNS"
spec:
  replicas: 2
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 1
  selector:
    matchLabels:
      k8s-app: kube-dns
  template:
    metadata:
      labels:
        k8s-app: kube-dns
    spec:
      priorityClassName: system-cluster-critical
      serviceAccountName: coredns
      tolerations:
        - key: "CriticalAddonsOnly"
          operator: "Exists"
      nodeSelector:
        beta.kubernetes.io/os: linux
      containers:
      - name: coredns
        image: coredns/coredns:1.3.1
        imagePullPolicy: IfNotPresent
        resources:
          limits:
            memory: 170Mi
          requests:
            cpu: 100m
            memory: 70Mi
        args: [ "-conf", "/etc/coredns/Corefile" ]
        volumeMounts:
        - name: config-volume
          mountPath: /etc/coredns
          readOnly: true
        ports:
        - containerPort: 53
          name: dns
          protocol: UDP
        - containerPort: 53
          name: dns-tcp
          protocol: TCP
        - containerPort: 9153
          name: metrics
          protocol: TCP
        securityContext:
          allowPrivilegeEscalation: false
          capabilities:
            add:
            - NET_BIND_SERVICE
            drop:
            - all
          readOnlyRootFilesystem: true
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
            scheme: HTTP
          initialDelaySeconds: 60
          timeoutSeconds: 5
          successThreshold: 1
          failureThreshold: 5
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
            scheme: HTTP
      dnsPolicy: Default
      volumes:
        - name: config-volume
          configMap:
            name: coredns
            items:
            - key: Corefile
              path: Corefile
---
apiVersion: v1
kind: Service
metadata:
  name: kube-dns
  namespace: kube-system
  annotations:
    prometheus.io/port: "9153"
    prometheus.io/scrape: "true"
  labels:
    k8s-app: kube-dns
    kubernetes.io/cluster-service: "true"
    kubernetes.io/name: "CoreDNS"
spec:
  selector:
    k8s-app: kube-dns
  clusterIP: "$service_dns"
  ports:
  - name: dns
    port: 53
    protocol: UDP
  - name: dns-tcp
    port: 53
    protocol: TCP
  - name: metrics
    port: 9153
    protocol: TCP
EOFG4

#部署dns自动扩容				
cat > dns-horizontal-autoscaler.yaml << EOFG5
# Copyright 2016 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

kind: ServiceAccount
apiVersion: v1
metadata:
  name: kube-dns-autoscaler
  namespace: kube-system
  labels:
    addonmanager.kubernetes.io/mode: Reconcile
---
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: system:kube-dns-autoscaler
  labels:
    addonmanager.kubernetes.io/mode: Reconcile
rules:
  - apiGroups: [""]
    resources: ["nodes"]
    verbs: ["list"]
  - apiGroups: [""]
    resources: ["replicationcontrollers/scale"]
    verbs: ["get", "update"]
  - apiGroups: ["extensions"]
    resources: ["deployments/scale", "replicasets/scale"]
    verbs: ["get", "update"]
# Remove the configmaps rule once below issue is fixed:
# kubernetes-incubator/cluster-proportional-autoscaler#16
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get", "create"]
---
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: system:kube-dns-autoscaler
  labels:
    addonmanager.kubernetes.io/mode: Reconcile
subjects:
  - kind: ServiceAccount
    name: kube-dns-autoscaler
    namespace: kube-system
roleRef:
  kind: ClusterRole
  name: system:kube-dns-autoscaler
  apiGroup: rbac.authorization.k8s.io

---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kube-dns-autoscaler
  namespace: kube-system
  labels:
    k8s-app: kube-dns-autoscaler
    kubernetes.io/cluster-service: "true"
    addonmanager.kubernetes.io/mode: Reconcile
spec:
  selector:
    matchLabels:
      k8s-app: kube-dns-autoscaler
  template:
    metadata:
      labels:
        k8s-app: kube-dns-autoscaler
      annotations:
        scheduler.alpha.kubernetes.io/critical-pod: ''
    spec:
      priorityClassName: system-cluster-critical
      containers:
      - name: autoscaler
        image: gcr.azk8s.cn/google_containers/cluster-proportional-autoscaler-amd64:1.1.2-r2
        resources:
            requests:
                cpu: "20m"
                memory: "10Mi"
        command:
          - /cluster-proportional-autoscaler
          - --namespace=kube-system
          - --configmap=kube-dns-autoscaler
          # Should keep target in sync with cluster/addons/dns/kube-dns.yaml.base
          - --target=Deployment/coredns
          # When cluster is using large nodes(with more cores), "coresPerReplica" should dominate.
          # If using small nodes, "nodesPerReplica" should dominate.
          - --default-params={"linear":{"coresPerReplica":256,"nodesPerReplica":16,"preventSinglePointFailure":true}}
          - --logtostderr=true
          - --v=2
      tolerations:
      - key: "CriticalAddonsOnly"
        operator: "Exists"
      serviceAccountName: kube-dns-autoscaler
EOFG5