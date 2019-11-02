FROM ubuntu:bionic
ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8

RUN apt-get update
RUN apt-get -y upgrade
RUN apt-get -y install wget python3-pip nodejs git
RUN pip3 install pipenv

WORKDIR lookyloo

COPY lookyloo lookyloo/
COPY client client/
COPY bin bin/
COPY website website/
COPY setup.py .
COPY Pipfile .
COPY Pipfile.lock .

RUN mkdir cache user_agents scraped

RUN pipenv install
RUN echo LOOKYLOO_HOME="'`pwd`'" > .env
