FROM ubuntu:bionic
ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8

RUN apt-get update
RUN apt-get -y upgrade
RUN apt-get -y install git wget python3-pip
RUN pip3 install pipenv

WORKDIR root_lookyloo

run git clone https://github.com/antirez/redis.git
run cd redis && git checkout 5.0 && make && cd ..

RUN git clone https://github.com/CIRCL/lookyloo.git
WORKDIR lookyloo
RUN sed -i "s/str='http:\/\/127.0.0.1:8050'/str='http:\/\/splash:8050'/g" lookyloo/lookyloo.py
RUN pipenv install
run echo LOOKYLOO_HOME="'`pwd`'" > .env

run nohup pipenv run run_backend.py --start
run nohup pipenv run async_scrape.py
CMD ["pipenv", "run", "start_website.py"]
EXPOSE 5100
