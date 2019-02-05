FROM ubuntu:bionic
ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8

RUN apt-get update
RUN apt-get -y upgrade
RUN apt-get -y install git wget python3-pip pwgen
RUN pip3 install pipenv

run git clone https://github.com/antirez/redis.git
run cd redis && git checkout 5.0 && make && cd ..

RUN git clone https://github.com/CIRCL/lookyloo.git
WORKDIR lookyloo
RUN pipenv install
run echo LOOKYLOO_HOME="'`pwd`'" > .env

RUN sed -i "s/SPLASH = 'http:\/\/127.0.0.1:8050'/SPLASH = 'http:\/\/splash:8050'/g" lookyloo/__init__.py

EXPOSE 5200
ENTRYPOINT ["pipenv", "run", "start.py"]
