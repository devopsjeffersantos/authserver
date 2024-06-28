FROM azul/zulu-openjdk-alpine:21
EXPOSE 9000
COPY target/*.jar authserver-0.0.1-SNAPSHOT.jar
ENTRYPOINT ["java","-jar","/authserver-0.0.1-SNAPSHOT.jar"]
