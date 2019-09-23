FROM gradle:4.10-jdk11-slim

USER root

ENV APP_HOME=/usr/local

RUN apt-get update \
    && apt-get install -y git unzip

RUN rm -rf /var/lib/apt/lists/*

RUN mkdir -p /usr/local/src \
    && cd /usr/local/src \
    && git clone https://github.com/opencadc/ac.git \
    && cd ac/cadc-access-control \
    && gradle -i clean build test

RUN cd /usr/local/src/ac/cadc-access-control/build/distributions \
    && export DIST_FILE_PREFIX=`ls *.zip | awk -F "\.zip" '{print $1}'` \
    && unzip ${DIST_FILE_PREFIX}.zip \
    && cp ${DIST_FILE_PREFIX}/lib/* /usr/local/lib/ \
    && cp ${DIST_FILE_PREFIX}/bin/* /usr/local/bin/

CMD [ "/usr/local/bin/cadc-access-control" ]