# First stage: GraalVM Native Image Builder
FROM container-registry.oracle.com/graalvm/native-image:21 AS nativebuild

WORKDIR /app
COPY .mvn/ .mvn/
COPY mvnw pom.xml ./

RUN chmod +x mvnw

# Pre-download dependencies
RUN ./mvnw dependency:go-offline
COPY src ./src

# Build a dynamically linked native image with optimization for size
RUN ./mvnw -Pnative -Dmaven.test.skip=true package

# Second stage: Runtime Image
FROM gcr.io/distroless/java-base-debian12
COPY --from=nativebuild /app/target/t4m-user-manager /
ENTRYPOINT ["/t4m-user-manager", "-b", "0.0.0.0", "-d", "/web"]