FROM gcr.io/forgerock-io/am-base:7.0.0
USER root

RUN apt-get update && apt-get install -y git

USER forgerock

# IAM-434: Preserves the native XUI code in a new location specifically for OAuth 2-related UI needs.
RUN cp -R /usr/local/tomcat/webapps/am/XUI /usr/local/tomcat/webapps/am/OAuth2_XUI
ENV CATALINA_USER_OPTS -Dorg.forgerock.am.oauth2.consent.xui_path=/OAuth2_XUI

COPY  --chown=forgerock:root config/ /home/forgerock/openam/config/

# Use a custom logback. Comment out if you want to use the default json logger.
COPY --chown=forgerock:root logback.xml /usr/local/tomcat/webapps/am/WEB-INF/classes

COPY --chown=forgerock:root lib/* /usr/local/tomcat/webapps/am/WEB-INF/lib/

COPY --chown=forgerock:root *.sh /home/forgerock/

COPY --chown=forgerock:root server.xml /usr/local/tomcat/conf

WORKDIR /home/forgerock/openam

# This lets the user see what FBC files have been modified
RUN git config --global user.email "cloud-deployment@forgerock.com" && \
    git config --global user.name "Cloud Deployment" && \
    git add . && \
    git commit -m "CDM file-based configuration overlay"

WORKDIR /home/forgerock

# If you want to debug AM uncomment these lines:
#ENV JPDA_TRANSPORT=dt_socket
#ENV JPDA_ADDRESS *:9009

# Lower RAM percentage for more stability on smaller images
ENV AM_CONTAINER_JVM_ARGS="-XX:MaxRAMPercentage=50 \
    -XX:InitialRAMPercentage=50 \
    -XX:MaxTenuringThreshold=1 \
    -Djava.security.egd=file:/dev/urandom"


ENTRYPOINT ["/home/forgerock/custom-entrypoint.sh"]
