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
kubectl  exec -it dockerdemo1-7c66cf67bc-qw6xv -- curl http://dockerdemo2:8080
# Check from other namespace
kubectl -n default apply -f root.yaml
kubectl -n default exec -it root -- wget https://dockerdemo2.security:8080

# default np deny all ingress
kubectl apply -f np-deny-ingress.yaml

# Check appli internally
kubectl  exec -it dockerdemo1-7c66cf67bc-qw6xv -- curl http://dockerdemo2:8080

# Check external connectivity
kubectl  exec -it dockerdemo1-7c66cf67bc-qw6xv -- ping www.google.fr

# default np allow in namespace
kubectl apply -f apply -f np-allow-ns.yaml

# Check from same namespace
kubectl  exec -it dockerdemo1-7c66cf67bc-qw6xv -- curl http://dockerdemo2:8080

# Check from other namespace
kubectl -n default exec -it root -- wget https://dockerdemo2.security:8080

# Appli still down from web browser
kubectl apply -f np-allow-infra.yaml

# Patch namespace infra
kubectl edit namespace ingress-nginx

# Deny all egress traffic
kubectl apply -f np-deny-egress.yaml

kubectl  exec -it dockerdemo1-7c66cf67bc-qw6xv -- ping www.google.fr
kubectl  exec -it dockerdemo1-7c66cf67bc-qw6xv -- curl http://dockerdemo2:8080

# Allow egress in same namespace
kubectl apply -f np-allow-ns-egress.yaml

# Allow dns
kubectl apply -f np-allow-egress-dns.yaml

# ######################################
# RBAC
# ######################################

# ######################################
# SECRETS VAULT
# ######################################

# ######################################
# CERT MANAGER
# ######################################

# ######################################
# OPA / GATEKEEPER
# ######################################

# ######################################
# HELM CHARTS DTR
# ######################################

# Cleanup
kubectl create clusterrolebinding ucp:all:privileged-psp-role --clusterrole=privileged-psp-role --group=system:authenticated --group=system:serviceaccounts
# or kubectl apply -f ucp-all-privileged-psp-role.yaml
kubectl delete namespace security