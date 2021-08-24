FROM ubuntu:focal
ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8

RUN apt-get update
RUN apt-get -y upgrade
RUN apt-get -y install wget python3-dev git python3-venv python3-pip python-is-python3
RUN pip3 install poetry

WORKDIR lookyloo

COPY lookyloo lookyloo/
COPY tools tools/
COPY bin bin/
COPY website website/
COPY setup.py .
COPY pyproject.toml .
COPY poetry.lock .
COPY README.md .

RUN mkdir cache user_agents scraped

RUN poetry install
RUN echo LOOKYLOO_HOME="'`pwd`'" > .env
RUN poetry run tools/3rdparty.py
