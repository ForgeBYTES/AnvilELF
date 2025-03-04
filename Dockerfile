FROM python:3.11

WORKDIR /src
COPY . /src

RUN apt update &&  \
    apt install -y gcc && \
    pip install -r /src/requirements-dev.txt
