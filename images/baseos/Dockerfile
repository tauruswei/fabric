# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

#FROM debian:buster-20190910-slim
FROM arm64v8/debian:buster
#COPY ./scripts /tmp/scripts
#RUN cd /tmp/scripts && \
#    common/init.sh && \
#    docker/init.sh && \
#    common/cleanup.sh && \
#    rm -rf /tmp/scripts
COPY scripts /tmp/scripts
RUN cd /tmp/scripts && \
    common/init.sh && \
    docker/init.sh && \
    common/cleanup.sh && \
    rm -rf /tmp/scripts
