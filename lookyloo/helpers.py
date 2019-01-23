#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
from pathlib import Path
from .exceptions import MissingEnv


def get_homedir():
    if not os.environ.get('LOOKYLOO_HOME'):
        guessed_home = Path(__file__).resolve().parent.parent
        raise MissingEnv(f"LOOKYLOO_HOME is missing. \
Run the following command (assuming you run the code from the clonned repository):\
    export LOOKYLOO_HOME='{guessed_home}'")
    return Path(os.environ['LOOKYLOO_HOME'])
