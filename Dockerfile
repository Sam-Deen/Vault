FROM maven:3.9.16-eclipse-temurin-21 AS build
WORKDIR /build
COPY pom.xml .
COPY src/main ./src/main
RUN mvn -B -ntp -Dmaven.test.skip=true package

FROM eclipse-temurin:21-jre-alpine
RUN addgroup -S vault && adduser -S -G vault vault
WORKDIR /app
COPY --from=build --chown=vault:vault /build/target/vault-0.0.1-SNAPSHOT.jar app.jar
USER vault
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
