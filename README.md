```sh
# Build
docker build -t dockerpac/alpine:root -f Dockerfile.alpineroot . && docker push dockerpac/alpine:root 
docker build -t dockerpac/alpine:notrootnotuid -f Dockerfile.alpinenotrootnotuid . && docker push dockerpac/alpine:notrootnotuid
docker build -t dockerpac/alpine:notroot -f Dockerfile.alpinenotroot . && docker push dockerpac/alpine:notroot
docker build -t dockerpac/tomcatsample:latest -f Dockerfile.tomcat . && docker push dockerpac/tomcatsample:latest
docker build -t dockerpac/tomcatsample:uncompressed -f Dockerfile.tomcatuncompressed . && docker push dockerpac/tomcatsample:uncompressed

# Preparation
cd ~/Dev/security
kubectl create namespace security
kubens security

# ######################################
# ROOT
# ######################################
# Allow all / root alpine
kubectl apply -f root.yaml

# Prevent root
kubectl apply -f preventroot.yaml

# Prevent root / not uid
kubectl apply -f preventrootnotuid.yaml

# Prevent root / OK
kubectl apply -f notroot.yaml

# But sudo is permitted !!
kubectl exec -it notroot -- id
kubectl exec -it notroot -- sudo id

# Prevent privilege escalation
kubectl apply -f preventescalation.yaml
kubectl exec -it preventescalation -- sudo id


# ######################################
# FSGROUP
# ######################################

# Create pvc
kubectl apply -f pvc-disk.yaml

# Create file as uid 1000
kubectl apply -f run1000.yaml
kubectl exec -it run1000 -- touch /demo/file1
kubectl exec -it run1000 -- ls -la /demo/
kubectl delete -f run1000.yaml

# Create file as uid 2000
kubectl apply -f run2000.yaml
kubectl exec -it run2000 -- touch /demo/file2
kubectl exec -it run2000 -- ls -la /demo/
kubectl exec -it run2000 -- rm /demo/file1
kubectl delete -f run2000.yaml


# ######################################
# CAPABILITIES
# ######################################
# https://docs.docker.com/engine/security/security/#linux-kernel-capabilities
# https://github.com/moby/moby/blob/298ba5b13150bfffe8414922a951a7a793276d31/oci/caps/defaults.go#L4
# https://github.com/torvalds/linux/blob/master/include/uapi/linux/capability.h
kubectl exec -it root -- ash
  id
  ping -c1 www.google.fr
kubectl apply -f dropcap.yaml
kubectl exec -it dropcap -- ash
  id
  ping -c1 www.google.fr

# Privileged

# ######################################
# READONLY
# ######################################

# Tomcat rw
kubectl apply -f tomcatrw.yaml
kubectl port-forward tomcatrw 8080:8080

# Tomcat readonly
kubectl apply -f tomcat.yaml
kubectl port-forward tomcat 8080:8080

# Tomcat readonly uncompressed
kubectl apply -f tomcatuncompressed.yaml
kubectl port-forward tomcatuncompressed 8080:8080

# Tomcat logs
# https://capstonec.com/getting-tomcat-logs-from-kubernetes-pods/
kubectl apply -f tomcatlogs.yaml
kubectl logs tomcatlogs -c filebeat-sidecar -f
kubectl port-forward tomcatlogs 8080:8080


# ######################################
# DISK USAGE
# ######################################
# Disk usage

kubectl get pods tomcatrw -o wide
# ssh / docker inspect
kubectl get pods tomcat -o wide
kubectl get pods tomcat -o jsonpath={.metadata.uid}
# Space is on node in /var/lib/kubelet

# Quota
kubectl apply -f quota.yaml
kubectl exec -it quota -- ash
  cd /test
  dd if=/dev/zero of=file.txt count=1024 bs=1048576
kubectl describe pod quota

# ######################################
# ENFORCEMENT / CONFTEST
# ######################################

# https://github.com/instrumenta/conftest
cd ~/Dev/security/conftest_kube
conftest test deployment_invalid.yaml
conftest test deployment_valid.yaml

cd ~/Dev/security/conftest_docker1
conftest test Dockerfile

cd ~/Dev/security/conftest_docker2
conftest test Dockerfile

cd ~/Dev/security


# ######################################
# IMAGE (PULL POLICY / SECRET)
# ######################################
kubectl apply -f registry-dockerdemo.yaml
kubectl describe pod registry-dockerdemo

# Create DTR TOKEN

# Create Secret holding registry creds
kubectl create secret docker-registry regcred --docker-server=dtr.pac2.demo-azure-cs.mirantis.com --docker-username=admin --docker-password=ea9cb2be-5c40-449b-8d18-c3776fcd4239 --docker-email=me@me.com

kubectl get secrets
kubectl describe secret regcred

kubectl apply -f registry-dockerdemo-regcred.yaml
kubectl describe pod registry-dockerdemo-regcred

# Patch default service account
kubectl get serviceaccount
kubectl describe serviceaccount default

kubectl patch serviceaccount default -p '{"imagePullSecrets": [{"name": "regcred"}]}'

# Revert
kubectl delete serviceaccount default

# Note about using ImagePullPolicy: Always
# (from K8S documentation) Note: The caching semantics of the underlying image provider make even imagePullPolicy: Always efficient. With Docker, for example, if the image already exists, the pull attempt is fast because all image layers are cached and no image download is needed.

# ######################################
# POD SECURITY POLICY
# ######################################

# Create user toto and gives grants
kubectl apply -f rbac_toto.yaml

# AdmissionController PodSecurityPolicy
# https://kubernetes.io/blog/2019/03/21/a-guide-to-kubernetes-admission-controllers/
# https://docs.docker.com/ee/ucp/kubernetes/pod-security-policies

# UCP Secure defaults
# https://docs.docker.com/ee/ucp/authorization/#secure-kubernetes-defaults

# https://kubernetes.io/docs/concepts/policy/pod-security-policy/#policy-reference

# Get UCP PSP
kubectl get podsecuritypolicies | grep privileged
kubectl get psp privileged -o yaml | grep -A100 spec:
kubectl get psp unprivileged -o yaml | grep -A100 spec:

# RBAC PSP
kubectl get clusterrole | grep privileged
kubectl get clusterrole privileged-psp-role -o yaml | grep -A100 rules:
kubectl get clusterrole unprivileged-psp-role -o yaml | grep -A100 rules:

# ucp:all:privileged-psp-role is applied to every users / service accounts
kubectl get clusterrolebinding | grep privileged
kubectl get clusterrolebinding ucp:all:privileged-psp-role -o yaml | grep -A100 roleRef:

# Check default PSP applied
# Switch user
kubectx pac2-toto
kubectl delete -f root.yaml --grace-period=0
kubectl apply -f root.yaml

kubectl describe pod root | grep -A1 Annotations:

# delete privileged
kubectx pac2-admin
kubectl delete clusterrolebinding ucp:all:privileged-psp-role 

# Re test user toto / no PSP found
kubectx pac2-toto
kubectl delete -f root.yaml --grace-period=0
kubectl apply -f root.yaml

# Create PSP with restrictions enforced
kubectx pac2-admin
kubectl apply -f psp-restricted-bad.yaml

# Re test user toto / psp-restricted applied
kubectx pac2-toto
kubectl apply -f root.yaml

kubectl describe pod root | grep -A1 Annotations:
kubectl describe pod root

# As cluster-admin create Pod --> OK
kubectx pac2-admin
kubectl delete -f root.yaml --grace-period=0
kubectl apply -f root.yaml

kubectl describe pod root | grep -A1 Annotations:
kubectl describe pod root

# As cluster-admin create Deployment --> KO!
kubectl apply -f deploy-root.yaml

# Create correct psp-restricted
kubectl apply -f psp-restricted-good.yaml

k describe pod deploy-root-xxx | grep -A1 Annotations:


# As toto, create Pod with restrictions
kubectx pac2-toto
kubectl delete -f preventescalation.yaml --grace-period=0
kubectl apply -f preventescalation.yaml

kubectl describe pod preventescalation | grep -A1 Annotations:

# Best practices
# https://capstonec.com/hands-on-with-kubernetes-pod-security-policies/

# Assign psp-restricted globally on the cluster
kubectl -n default apply -f root.yaml

kubectx pac2-admin
kubectl apply -f psp-restricted-best.yaml

kubectx pac2-toto
kubectl -n default apply -f root.yaml
kubectl -n default describe pod root | grep -A1 Annotations:

# Assign the psp-privileged to infra namespaces
kubectx pac2-admin
kubectl apply -f psp-privileged-infra.yaml

kubectx pac2-toto
kubectl -n monitoring apply -f root.yaml
kubectl -n monitoring describe pod root | grep -A1 Annotations:


# check seccomp
# https://docs.docker.com/engine/security/seccomp/
kubectl exec -it preventescalation -- grep Seccomp /proc/1/status

# Revert privileged PSP for ALL
kubectx pac2-admin
kubectl create clusterrolebinding ucp:all:privileged-psp-role --clusterrole=privileged-psp-role --group=system:authenticated --group=system:serviceaccounts
kubectl delete -f psp-restricted-good.yaml
kubectl delete -f psp-restricted-best.yaml
kubectl delete -f psp-privileged-infra.yaml
# or kubectl apply -f ucp-all-privileged-psp-role.yaml


# ######################################
# NETWORK POLICY
# ######################################
kubectl apply -f dockerdemo1.yaml -f dockerdemo2.yaml

# Check appli using browser
# Check appli internally
kubectl  exec -it deploy/dockerdemo1 -- curl http://dockerdemo2:8080
# Check from other namespace
kubectl -n default apply -f root.yaml
kubectl -n default exec -it root -- apk add curl
kubectl -n default exec -it root -- curl  http://dockerdemo2:8080
kubectl -n default exec -it root -- curl http://dockerdemo2.security:8080

# default np deny all ingress
kubectl apply -f np-deny-ingress.yaml

# Check appli internally
kubectl  exec -it deploy/dockerdemo1 -- curl http://dockerdemo2:8080

# Check external connectivity
kubectl  exec -it deploy/dockerdemo1 -- ping www.google.fr

# default np allow in namespace
kubectl apply -f np-allow-ns.yaml

# Check from same namespace
kubectl  exec -it deploy/dockerdemo1 -- curl http://dockerdemo2:8080

# Check from other namespace
kubectl -n default exec -it root -- wget https://dockerdemo2.security:8080

# Appli still down from web browser
kubectl apply -f np-allow-infra.yaml

# Patch namespace infra
kubectl edit namespace ingress-nginx

# Deny all egress traffic
kubectl apply -f np-deny-egress.yaml

kubectl  exec -it deploy/dockerdemo1 -- ping www.google.fr
kubectl  exec -it deploy/dockerdemo1 -- curl http://dockerdemo2:8080

# Allow egress in same namespace
kubectl apply -f np-allow-ns-egress.yaml
kubectl  exec -it deploy/dockerdemo1 -- curl http://dockerdemo2:8080

# Allow dns
kubectl apply -f np-allow-egress-dns.yaml

# Kubernetes NetworkPolicy
 # policies are limited to an environment;
 # policies are applied to pods marked with labels;
 # you can apply rules to pods, environments or subnets;
 # the rules may contain protocols, numerical or named ports.

# Calico NetworkPolicy
# policies can be applied to any object: pod, container, virtual machine or interface;
# the rules can contain the specific action (restriction, permission, logging);
# you can use ports, port ranges, protocols, HTTP/ICMP attributes, IPs or subnets (v4 and v6), any selectors (selectors for nodes, hosts, environments) as a source or a target of the rules;
# also, you can control traffic flows via DNAT settings and policies for traffic forwarding.


# CLEANUP
kubectl delete networkpolicy --all

# ######################################
# RBAC
# ######################################

# ######################################
# SECRETS VAULT
# ######################################
# https://www.vaultproject.io/docs/platform/k8s/injector

# Deploy Vault
helm repo add hashicorp https://helm.releases.hashicorp.com
helm search repo hashicorp/vault -l
kubectl create ns vault
helm -n vault install vault hashicorp/vault -f vault-values.yaml


# Check MutatingWebHook
kubectl get mutatingwebhookconfigurations
kubectl describe mutatingwebhookconfigurations vault-agent-injector-cfg


# Configure Vault
kubectl -n vault exec -it vault-0 -- /bin/sh

# Create policy
cat <<EOF > /home/vault/app-policy.hcl
path "secret*" {
  capabilities = ["read"]
}
EOF

vault policy write app /home/vault/app-policy.hcl

# Enable auth
vault auth enable kubernetes

vault write auth/kubernetes/config \
   token_reviewer_jwt="$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
   kubernetes_host=https://${KUBERNETES_PORT_443_TCP_ADDR}:443 \
   kubernetes_ca_cert=@/var/run/secrets/kubernetes.io/serviceaccount/ca.crt

vault write auth/kubernetes/role/myapp \
   bound_service_account_names=app \
   bound_service_account_namespaces=demo \
   policies=app \
   ttl=1h

# Create secret
vault kv put secret/helloworld username=foobaruser password=foobarbazpass
exit


# Deploy vault demo app
kubectl apply -f vault-app.yaml
kubectl exec deploy/app -c app -- ls -l /vault/secrets
kubectl delete -f vault-app.yaml 

kubectl apply -f vault-app-with-secret.yaml
# initContainer failed
kubectl get pods
kubectl logs deploy/app -c vault-agent-init

kubectl delete -f vault-app-with-secret.yaml

kubectl -n demo apply -f vault-app-with-secret.yaml
kubectl -n demo logs deploy/app -c vault-agent-init
kubectl -n demo logs deploy/app -c vault-agent
kubectl -n demo logs deploy/app -c app

# Deployment is not modified, only Pod
kubectl -n demo get deploy/app -o yaml

# Secrets
kubectl -n demo exec deploy/app -c app -- ls -l /vault/secrets
kubectl -n demo exec deploy/app -c app -- cat /vault/secrets/helloworld

# Template
kubectl -n demo apply -f vault-app-with-secret-with-template.yaml
kubectl -n demo exec deploy/app -c app -- cat /vault/secrets/helloworld

kubectl -n demo delete -f vault-app-with-secret.yaml



# ######################################
# CERT MANAGER
# ######################################

# Installation
kubectl apply --validate=false -f https://github.com/jetstack/cert-manager/releases/download/v0.15.0/cert-manager.crds.yaml
helm repo add jetstack https://charts.jetstack.io
kubectl create namespace cert-manager
helm install cert-manager --namespace cert-manager jetstack/cert-manager


# Generate private PKI
cd pki
openssl genrsa -out rootCA.key 4096
openssl req -x509 -new -nodes -key rootCA.key -sha256 -days 1024 -out rootCA.crt -extensions v3_ca -config openssl-with-ca.cnf

# Create Secret with rootCA
kubectl create secret tls ca-key-pair --key pki/rootCA.key --cert pki/rootCA.crt

# Create Issuer / Type CA
kubectl apply -f issuer.yaml

kubectl describe issuer ca-issuer

# Create Certificate
kubectl apply -f certificate.yaml
kubectl get certificate,certificaterequest

kubectl get secret

kubectl delete certificate selfsigned-crt
kubectl delete secret selfsigned-crt-secret


# Automate Ingress TLS
kubectl apply -f dockerdemo-tls.yaml

kubectl get certificate,certificaterequest

kubectl delete -f dockerdemo-tls.yaml
kubectl delete secret dockerdemotls

# ######################################
# HELM CHARTS DTR
# ######################################

cd helm
docker build -t dockerpac/helm:latest .
# PUSH
docker run --rm -it --rm dockerpac/helm:latest
helm repo add stable https://kubernetes-charts.storage.googleapis.com
helm pull stable/prometheus-operator --untar
helm chart save ./prometheus-operator dtr.pac2.demo-azure-cs.mirantis.com/admin/prometheus-operator:latest
helm registry login dtr.pac2.demo-azure-cs.mirantis.com

helm chart push dtr.pac2.demo-azure-cs.mirantis.com/admin/prometheus-operator:latest
exit

# PULL
docker run --rm -it --rm dockerpac/helm:latest
helm chart list
ls
helm chart pull dtr.pac2.demo-azure-cs.mirantis.com/admin/prometheus-operator:latest
helm chart export dtr.pac2.demo-azure-cs.mirantis.com/admin/prometheus-operator:latest
helm template prometheus-operator 2>/dev/null| tail -50

# CLEANUP
kubectl delete namespace security

# ######################################
# OPA / GATEKEEPER
# ######################################

# https://play.openpolicyagent.org/

# Gatekeeper

# Centralized management of all your policies (PSP and other custom policies) in one admission controller instead of managing those disparately.
# Shift-Left – Enforce the same policies also in the CI/CD pipeline thus implementing Policy-as-code throughout the stack.
# Ability to maintain OPA policies in a source control repository like Git. OPA provides http APIs to dynamically manage the policies loaded.
# Stream the policy decisions to an external logging / monitoring tool of your choice.
# Customize the denial message as per your setup/implementation.

# Deploy Gatekeeper
kubectl apply -f gatekeeper.yaml

kubectl get validatingwebhookconfigurations
kubectl get validatingwebhookconfigurations gatekeeper-validating-webhook-configuration -o yaml


# Install Policykit
pip3 install policykit

# Test compliance
pk build policy/k8sallowedrepos.rego

kubectl apply -f policy/k8sallowedrepos.yaml
kubectl get constrainttemplates
kubectl get crds

kubectl apply -f check_repo_dtr.yaml
kubectl get k8sallowedrepos

# Look for status
kubectl describe k8sallowedrepos security-repo-is-dtr

# Create wrong repo
kubectl apply -f root.yaml

# Correct
kubectl apply -f root-dtr.yaml

pk build policy/k8suniqueingresshost.rego

kubectl apply -f policy/k8suniqueingresshost.yaml
kubectl get constrainttemplates
kubectl get crds

 kubectl apply -f check_unique_ingress.yaml

 kubectl apply -f sync.yaml
 kubectl apply -f ingress1.yaml
 kubectl apply -f ingress2.yaml

# Cleanup
kubectl delete k8suniqueingresshost unique-ingress-host
kubectl delete k8sallowedrepos security-repo-is-dtr
kubectl delete constrainttemplates k8sallowedrepos
kubectl delete constrainttemplates k8suniqueingresshost
kubectl delete -f gatekeeper.yaml


# Constraint Library : 
# https://github.com/open-policy-agent/gatekeeper/tree/master/library

# Rego block other DTR

# Rego block replicas

# Rego block labels

# All ingress hostnames must be globally unique

# Restrict PV name

# Restrict Tolerations

# ######################################
# MINIO
# ######################################
# Prereq
# Default StorageClass with RWO
# Deploy minio operator
# https://github.com/minio/minio-operator/blob/master/README.md
cd minio-operator/
cd operator-deployment
kustomize build | kubectl apply -f -
cd ..

cd examples
# Change default storage from 1Ti to 1Gi
kubectl -n default apply -f minioinstance.yaml

# Access UI
# Show password
echo $(kubectl -n default get secret minio-creds-secret -o=jsonpath='{.data.secretkey}' -n default |base64 --decode)

kubectl -n default port-forward service/minio-service 9000

# Configure Minio client
mc config host add minio http://localhost:9000 minio minio123
mc admin info minio

# Configure RBAC
# https://docs.min.io/docs/minio-multi-user-quickstart-guide.html
mc admin user add minio user1 password
mc admin user add minio user2 password

```

