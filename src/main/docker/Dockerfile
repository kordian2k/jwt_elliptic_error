FROM python:latest
LABEL description="Reproducer for a validation error when using EC cryptography."
#################################################################################
#
# Add: OpenJDK support
# https://github.com/docker-library/openjdk/blob/415b0cc42d91ef5d70597d8a24d942967728242b/8-jdk/Dockerfile
#
#################################################################################
# A few problems with compiling Java from source:
#  1. Oracle.  Licensing prevents us from redistributing the official JDK.
#  2. Compiling OpenJDK also requires the JDK to be installed, and it gets
#       really hairy.

RUN apt-get update && apt-get install -y --no-install-recommends \
		bzip2 \
		unzip \
		xz-utils \
	&& rm -rf /var/lib/apt/lists/*

RUN echo 'deb http://deb.debian.org/debian jessie-backports main' > /etc/apt/sources.list.d/jessie-backports.list

# Default to UTF-8 file.encoding
ENV LANG C.UTF-8

# add a simple script that can auto-detect the appropriate JAVA_HOME value
# based on whether the JDK or only the JRE is installed
RUN { \
		echo '#!/bin/sh'; \
		echo 'set -e'; \
		echo; \
		echo 'dirname "$(dirname "$(readlink -f "$(which javac || which java)")")"'; \
	} > /usr/local/bin/docker-java-home \
	&& chmod +x /usr/local/bin/docker-java-home

# do some fancy footwork to create a JAVA_HOME that's cross-architecture-safe
RUN ln -svT "/usr/lib/jvm/java-8-openjdk-$(dpkg --print-architecture)" /docker-java-home
ENV JAVA_HOME /docker-java-home

ENV JAVA_VERSION 8u131
ENV JAVA_DEBIAN_VERSION 8u131-b11-1~bpo8+1

# see https://bugs.debian.org/775775
# and https://github.com/docker-library/java/issues/19#issuecomment-70546872
ENV CA_CERTIFICATES_JAVA_VERSION 20161107~bpo8+1

RUN set -ex; \
	\
	apt-get update; \
	apt-get install -y \
		openjdk-8-jdk="$JAVA_DEBIAN_VERSION" \
		ca-certificates-java="$CA_CERTIFICATES_JAVA_VERSION" \
	; \
	rm -rf /var/lib/apt/lists/*; \
	\
# verify that "docker-java-home" returns what we expect
	[ "$(readlink -f "$JAVA_HOME")" = "$(docker-java-home)" ]; \
	\
# update-alternatives so that future installs of other OpenJDK versions don't change /usr/bin/java
	update-alternatives --get-selections | awk -v home="$(readlink -f "$JAVA_HOME")" 'index($3, home) == 1 { $2 = "manual"; print | "update-alternatives --set-selections" }'; \
# ... and verify that it actually worked for one of the alternatives we care about
	update-alternatives --query java | grep -q 'Status: manual'

# see CA_CERTIFICATES_JAVA_VERSION notes above
RUN /var/lib/dpkg/info/ca-certificates-java.postinst configure

#################################################################################
#
# Install PyJWT
#
#################################################################################
RUN pip install pyjwt && pip install cryptography

#################################################################################
#
# Declare WORKDIR and generate certificates using keytool and openssl
#
#################################################################################
ENV EX_PATH /example
WORKDIR $EX_PATH

RUN apt-get update && apt-get install -y --no-install-recommends \
		openssl \
	&& rm -rf /var/lib/apt/lists/*

RUN keytool -genkeypair -keystore jwt_keystore.jceks -storetype jceks \
            -keyalg EC -keysize 256 -alias ES512 -sigalg SHA512withECDSA -validity 3600 \
            -dname "CN=someurl.jwt.error" \
            -storepass password -keypass password \
    && keytool -importkeystore -srckeystore jwt_keystore.jceks -destkeystore tmp_store.p12 \
            -srcstoretype jceks -deststoretype PKCS12 -destkeypass password -deststorepass password \
            -srcstorepass password \
    && openssl pkcs12 -in tmp_store.p12 -nokeys -out jwt_public.pem -passin pass:password \
    && openssl pkcs12 -in tmp_store.p12 -nodes -nocerts -out jwt_private_key.pem -passin pass:password

#################################################################################
#
# Copy fat jar and run reproducer
#
#################################################################################
COPY app/* $EX_PATH/
#CMD ["/bin/bash"]
CMD ["java", "-Dfile.encoding=UTF-8", "-jar", "jwt-elliptic-error-1.0-SNAPSHOT-fat.jar"]
