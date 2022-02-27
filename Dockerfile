FROM openjdk:11.0.7-jre-slim
RUN addgroup --system listshop-dash && adduser --system listshop-dash --ingroup listshop-dash
USER listshop-dash:listshop-dash
ARG DEPENDENCY=target/dependency
COPY ${DEPENDENCY}/BOOT-INF/lib /app/lib
COPY ${DEPENDENCY}/META-INF /app/META-INF
COPY ${DEPENDENCY}/BOOT-INF/classes /app
ENTRYPOINT ["java","-cp","app:app/lib/*","meg.tools.actuatoradmin.ActuatorAdminApplication"]