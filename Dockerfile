FROM ubuntu:bionic
ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8

RUN apt-get update
RUN apt-get -y upgrade
RUN apt-get -y install wget python3.7-dev git python3.7-venv python3-pip
RUN pip3 install poetry

WORKDIR lookyloo

COPY lookyloo lookyloo/
COPY client client/
COPY bin bin/
COPY website website/
COPY setup.py .
COPY pyproject.toml .
COPY poetry.lock .
COPY README.md .

RUN mkdir cache user_agents scraped

RUN poetry install
RUN echo LOOKYLOO_HOME="'`pwd`'" > .env
