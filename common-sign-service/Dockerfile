FROM inovus/openjdk:11_jdk_v1.0

EXPOSE 8080

ARG JAR_FILE
COPY ${JAR_FILE} app.jar
ENTRYPOINT ["java","-jar","app.jar","--server.port=8080"]