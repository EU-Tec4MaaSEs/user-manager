FROM maven:3.9.9-eclipse-temurin-21 AS build

COPY . /usr/src/app
WORKDIR /usr/src/app
RUN mvn -B -Dmaven.test.skip -f pom.xml clean package

FROM openjdk:21-jdk
COPY --from=build /usr/src/app/target/*.jar app.jar

ENTRYPOINT ["java", "-XX:+UseG1GC", "-jar", "/app.jar"]
