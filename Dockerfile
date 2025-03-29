FROM python:3.13

ARG UID=1000
ARG GID=1000

RUN groupadd -g ${GID} anvilelf
RUN useradd -m -u ${UID} -g ${GID} -s /bin/bash anvilelf

WORKDIR /src

COPY --chown=anvilelf:anvilelf . /src

RUN apt update && \
    apt install -y gcc && \
    pip install -r /src/requirements.txt -r /src/requirements-dev.txt

USER anvilelf
