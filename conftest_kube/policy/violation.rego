package main

import data.kubernetes

name = input.metadata.name

violation[{"msg": msg, "details": {}}] {
  kubernetes.is_service
  msg = sprintf("Found service %s but service are not allowed", [name])
}
