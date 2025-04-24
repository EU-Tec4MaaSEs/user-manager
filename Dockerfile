FROM container-registry.oracle.com/graalvm/native-image:21 AS nativebuild
COPY . /app
WORKDIR /app

RUN chmod +x mvnw
# Build a dynamically linked native image with optimization for size
RUN ./mvnw -Dmaven.test.skip=true -Pnative native:compile

# Distroless Java Base-provides glibc and other libraries needed by the JDK
FROM gcr.io/distroless/java-base-debian12
COPY --from=nativebuild /app/target/t4m-user-manager /
ENTRYPOINT ["/t4m-user-manager", "-b", "0.0.0.0", "-d", "/web"]