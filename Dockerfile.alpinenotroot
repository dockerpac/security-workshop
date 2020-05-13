FROM alpine:latest
RUN apk add sudo
RUN addgroup -g 1000 -S appgroup && adduser -u 1000 -S appuser -G appgroup
RUN addgroup -g 1500 -S appgroup2 && adduser -u 1500 -S appuser2 -G appgroup2
RUN echo 'ALL ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers
USER 1000
