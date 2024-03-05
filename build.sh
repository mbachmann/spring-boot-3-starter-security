#!/bin/sh

./mvnw clean package -Dmaven.test.skip=true
docker build -t uportal/spring-boot-3-starter-security .
