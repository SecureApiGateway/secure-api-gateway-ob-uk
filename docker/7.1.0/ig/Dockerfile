FROM gcr.io/forgerock-io/ig:7.1.0

# Base image is using the forgerock user, switch to root for priviledged tasks
USER root
# Replace any old repos with just Sid
RUN echo 'deb http://deb.debian.org/debian sid main' > /etc/apt/sources.list
# Upgrade minimal stack first
RUN apt-get update
# Next step will fail on https://bugs.debian.org/993755
#   /usr/bin/perl: error while loading shared libraries: libcrypt.so.1: cannot
#     open shared object file: No such file or directory
#   dpkg: error processing package libc6:amd64 (--configure):
RUN apt-get install -y apt || true
# Apply workaround
RUN cd $(mktemp -d)
RUN apt -y download libcrypt1
RUN dpkg-deb -x libcrypt1_*.deb .
RUN cp -ra lib/* /lib/
RUN find /lib/*/libcrypt.* -ls
RUN apt -y --fix-broken install
# Complete upgrade of minimal stack
RUN apt-get install -y apt
## install tools to edit the files in the container
RUN apt install nano vim -y
# test docker build from master
# Switching back to forgerock user, app will run as this
USER forgerock
# Create dir where secrets can be mounted into
RUN mkdir /var/ig/secrets
COPY --chown=forgerock:root bin/import-pem-certs.sh /home/forgerock
COPY --chown=forgerock:root lib /opt/ig/lib

# Copy all config files into the docker image.
# The default ig directory is /var/ig, and it expects subfolders config/ and scripts/ (if required)
COPY --chown=forgerock:root audit-schemas /var/ig/audit-schemas/
COPY --chown=forgerock:root scripts /var/ig/scripts/
COPY --chown=forgerock:root config /var/ig/config/
