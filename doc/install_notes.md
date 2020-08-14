# Requirements

* Ubuntu 20.04.1 (or equivalent) - Update all the things

```bash
sudo apt update
sudo apt dist-upgrade
```
* Packaged dependencies

```bash
sudo apt install build-essential
sudo apt install docker.io
sudo apt-get install python3-venv python3-dev
```

* poetry

```bash
curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py | python3
source $HOME/.poetry/env
```

* redis

```bash
git clone https://github.com/antirez/redis.git
cd redis
git checkout 6.0
make
cd ..
```
* Splash

```bash
sudo docker pull scrapinghub/splash:3.5.0
```
* lookyloo

```bash
git clone https://github.com/Lookyloo/lookyloo.git
cd lookyloo
poetry install
echo LOOKYLOO_HOME="'`pwd`'" > .env
```

# Configure lookyloo

```bash
cp config/generic.json.sample config/generic.json
cp config/modules.json.sample config/modules.json
```

And edit the files acordingly (see comments).

# Start the things

It is recommended to use tmux, and run the two following commands in 2 different shells

```bash
sudo docker run -p 8050:8050 -p 5023:5023 scrapinghub/splash:3.5.0 --disable-browser-caches
```

```bash
poetry run start.py
```
