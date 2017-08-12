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

We install python-qt4 and python3-pyqt4 systemwide because they are painful to install manually:

```bash
sudo apt-get install python-qt4 python3-pyqt4
```

## Server install (Ubuntu 16.04):

You need to install a basic X server:

```bash
apt-get install xserver-xorg xdm xfonts-base xfonts-100dpi xfonts-75dpi
```

And configure xdm in `/etc/X11/xdm/xdm-config`:

Replace:

```
DisplayManager*authorize:      true
```
with

```
DisplayManager*authorize:      false
```

And restart xdm:

```bash
service xdm restart
```

# Installation of scrapysplashwrapper

You need a running splash instance, preferably on docker: https://splash.readthedocs.io/en/stable/install.html

```bash
sudo apt install docker.io
sudo docker pull scrapinghub/splash
sudo docker run -p 8050:8050 -p 5023:5023 scrapinghub/splash

```

# Installation of the whole thing

If you have `pew` installed you can enable the use of pyqt4 installed globally this way (instead of installing PyQT4 manually):

```bash
pew toggleglobalsitepackages  # PyQt4 is not easily installable in a virtualenv
pip install -r requirements.txt
pip install -e .
```
# Run the app locally

```bash
export DISPLAY=:0
export FLASK_APP=lookyloo
flask run
```

## With a reverse proxy (Nginx)

```bash
pip install uwsgi
```

### Config files

You have to configure the two following files:

* `etc/nginxsites-available/lookyloo`
* `etc/systemd/system/lookyloo.service`

And copy them to the appropriate directories and run the following command:
```bash
sudo ln -s /etc/nginx/sites-available/lookyloo /etc/nginx/sites-enabled
```

If needed, remove the default site
```bash
sudo rm /etc/nginx/sites-enabled/default
```

Make sure everything is working:

```bash
sudo systemctl start lookyloo
sudo systemctl enable lookyloo
sudo nginx -t
# If it is cool:
sudo service restart nginx
```

And you can open http://<IP-or-domain>/

Now, you should configure TLS (let's encrypt and so on) -> https://www.digitalocean.com/community/tutorials/how-to-secure-nginx-with-let-s-encrypt-on-ubuntu-16-04

