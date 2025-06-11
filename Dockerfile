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
RUN ./mvnw clean package -Pnative -DskipTests -B \
    -Dspring.aot.enabled=true \
    -Dspring.native.remove-unused-autoconfig=true \
    -Dspring.jpa.defer-datasource-initialization=true \
    && strip target/t4m-user-manager

# Second stage: Runtime Image
FROM gcr.io/distroless/java-base-debian12

# Select default Non-root User
USER 65532:65532

COPY --from=nativebuild --chown=65532:65532 /app/target/t4m-user-manager /app/
WORKDIR /app

ENTRYPOINT ["/app/t4m-user-manager"]
CMD ["--server.address=0.0.0.0"]