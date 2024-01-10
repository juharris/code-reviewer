# Once a Mariner image with Python 3.10 becomes available, we should use that instead.
# FROM mcr.microsoft.com/cbl-mariner/base/python:3.10

# Until a Mariner image with Python 3.10 becomes available, we use the base image and install Python 3.10 ourselves.
FROM mcr.microsoft.com/cbl-mariner/base/core:2.0

# Please keep the commands below in order of longest-running to fastest to optimize docker build time.

RUN tdnf -y update && \
    tdnf -y install \
        build-essential \
        bzip2-devel \
        ca-certificates \
        gcc \
        libffi-devel \
        make \
        nginx \
        openssl-devel \
        tar \
        wget \
        zlib-devel && \
    tdnf clean all

WORKDIR /opt
ENV PYTHON_VERSION=3.10.13
RUN wget https://www.python.org/ftp/python/${PYTHON_VERSION}/Python-${PYTHON_VERSION}.tgz
RUN tar -xzf Python-${PYTHON_VERSION}.tgz
WORKDIR /opt/Python-${PYTHON_VERSION}
RUN ./configure --enable-optimizations
RUN make -j $(nproc)
RUN make install
RUN curl -sS https://bootstrap.pypa.io/get-pip.py | python3

WORKDIR /code

COPY requirements.txt .
RUN pip install --requirement requirements.txt

# Ordered by descending size.
COPY src ./src
COPY config.yml .
COPY run_inside_docker.sh .

# Expose nginx for the warmup request that Azure App Service sends.
EXPOSE 80

CMD bash run_inside_docker.sh

# Record the UTC timestamp from when the image was built.
# This will be echoed by run.py (if the file exists).
RUN echo $(date -u +"%Y-%m-%dT%H:%M:%SZ") > ./src/.docker_image_build_timestamp
