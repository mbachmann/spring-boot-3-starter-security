#
# Build stage
#
FROM maven:3.8.5-openjdk-17 AS build
ENV HOME=/usr/app
RUN mkdir -p $HOME
WORKDIR $HOME
ADD . $HOME
# RUN mvn -DskipTests -f /home/app/pom.xml clean package
#  daemon.json
# {
  #  "builder": {
  #    "gc": {
  #      "defaultKeepStorage": "20GB",
  #      "enabled": true
  #    }
  #  },
  #  "experimental": false,
  #  "features": {
  #    "buildkit": true
  #  }
  #}
# Use BuildKit cache for Maven dependencies
RUN --mount=type=cache,target=/root/.m2 mvn -DskipTests -f $HOME/pom.xml clean package

#
# Package stage
#
FROM openjdk:17-jdk-slim
ENV HOME=/usr/app
COPY --from=build $HOME/target/starter-*.jar /usr/local/lib/app.jar
ARG JVM_OPTS
ENV JVM_OPTS=${JVM_OPTS}
# COPY chatapp.keystore.jks /
EXPOSE 8080
ENTRYPOINT ["sh", "-c", "java $JVM_OPTS -jar /usr/local/lib/app.jar"]
