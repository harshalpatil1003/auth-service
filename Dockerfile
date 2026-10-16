# Runtime image for auth-service. Build the jar first (./mvnw clean package): the credintel-*
# libraries come from the internal Maven repository, which the image build can't reach.
FROM eclipse-temurin:17-jre

RUN groupadd --system app && useradd --system --gid app --home /app app
WORKDIR /app
COPY target/auth-service-*.jar app.jar
USER app

# 8083: API (reached through the gateway only); 8183: health, never published.
# Mount the production key pair (e.g. /keys) and point JWT_*_KEY_LOCATION at it.
EXPOSE 8083 8183

ENV SPRING_PROFILES_ACTIVE=prod \
    JAVA_OPTS="-XX:MaxRAMPercentage=75 -XX:+ExitOnOutOfMemoryError"

HEALTHCHECK --interval=30s --timeout=3s --start-period=60s --retries=3 \
  CMD wget -q -O /dev/null http://localhost:8183/actuator/health/liveness || exit 1

ENTRYPOINT ["sh", "-c", "exec java $JAVA_OPTS -jar /app/app.jar"]
