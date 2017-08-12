# Lookyloo

*Lookyloo* is a web interface allowing to scrape a website and then displays a
tree of domains calling each other.

# What is that name?!


```
1. People who just come to look.
2. People who go out of their way to look at people or something often causing crowds and more disruption.
3. People who enjoy staring at watching other peoples misfortune. Oftentimes car onlookers to car accidents.
Same as Looky Lou; often spelled as Looky-loo (hyphen) or lookylou
In L.A. usually the lookyloo's cause more accidents by not paying full attention to what is ahead of them.
```

Source: Urban Dictionary


# Implementation details

This code is very heavily inspired by https://github.com/etetoolkit/webplugin and adapted to use flask as backend.

# Installation of har2tree

The core dependency is ETE Toolkit, which you can install following the guide
on the official website: http://etetoolkit.org/download/

## Protip

If you like using virtualenv and have `pew` installed you can also do it this way:

```bash
sudo apt-get install python3-pyqt4
```

# Installation of scrapysplashwrapper

You need a running splash instance, preferably on docker: https://splash.readthedocs.io/en/stable/install.html

```bash
sudo apt install docker.io
sudo docker pull scrapinghub/splash
sudo docker run -p 8050:8050 -p 5023:5023 scrapinghub/splash

```

# Installation of the whole thing

(assuming you already installed the dependencies ete3 and splash in docker)

```bash
pew toggleglobalsitepackages  # PyQt4 is not easily installable in a virtualenv
pip install -r requirements.txt
pip install -e .
```
