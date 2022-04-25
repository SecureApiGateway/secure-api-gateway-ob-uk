FROM gcr.io/forgerock-io/ig:7.1.0

ENV JAVA_OPTS="-Dorg.forgerock.http.TrustTransactionHeader=true"
RUN echo "JAVA_OPTS set to ${JAVA_OPTS}"

RUN apt install vim
# Copy all config files into the docker image.
# The default ig directory is /var/ig, and it expects subfolders config/ and scripts/ (if required)

COPY --chown=forgerock:root . /var/ig
COPY --chown=forgerock:root lib /opt/ig/lib

USER root

RUN sed -i 's/stable\/updates/stable-security\/updates/' /etc/apt/sources.list

RUN apt-get update && apt-get install nano
