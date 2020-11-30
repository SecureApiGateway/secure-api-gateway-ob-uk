FROM openjdk:8-jre-alpine
ENV APP_FILE psd-2-rsc-sevice-0.0.2-SNAPSHOT.war
ENV APP_HOME usr/apps
EXPOSE 8083
COPY $APP_FILE $APP_HOME/
WORKDIR $APP_HOME
ENTRYPOINT ["sh", "-c"]
CMD ["exec java -Xms256M -Xmx512M -jar $APP_FILE"]
