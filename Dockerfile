# syntax=docker/dockerfile:1
#
# This Dockerfile is used to build the docker image for tzsp-proxy
#

# install depencencies and compile (this is a multi-stage build)
#
# python multi-stage build info: https://pythonspeed.com/articles/multi-stage-docker-python/
#
# the image used in this stage must include the compiler and build tools
FROM python:3 AS compile-image

# Keeps Python from generating .pyc files in the container
ENV PYTHONDONTWRITEBYTECODE=1

# Turns off buffering for easier container logging
ENV PYTHONUNBUFFERED=1

RUN apt-get update \
&& DEBIAN_FRONTEND=noninteractive \
   apt-get upgrade -yy

WORKDIR /opt/venv

# setup python virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt
COPY . .

# build the runtime image
#
# using -slim builds will reduce the number of vulnerabilities
FROM python:3-slim as runtime-image

# Keeps Python from generating .pyc files in the container
ENV PYTHONDONTWRITEBYTECODE=1

# Turns off buffering for easier container logging
ENV PYTHONUNBUFFERED=1

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive \
    apt-get upgrade -y \
 && apt-get install -y libpcap0.8

# copy compiled files into the runtime image
COPY --from=compile-image /opt/venv /opt/venv

# this is a module that must be run as root
USER root

# set the working directory
WORKDIR /opt/venv

# use the virtual environment
ENV PATH="/opt/venv/bin:$PATH"
# During debugging, this entry point will be overridden. For more information, please refer to https://aka.ms/vscode-docker-python-debug
CMD ["python", "tzsp-proxy.py"]
