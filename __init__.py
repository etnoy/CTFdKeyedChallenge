#!/usr/bin/env python
# -*- coding: utf-8 -*-
from CTFd.plugins.challenges import BaseChallenge
from CTFd.plugins import register_plugin_assets_directory
from CTFd.plugins.flags import get_flag_class
from CTFd.models import db, Solves, Fails, Flags, Challenges, ChallengeFiles, Tags, Teams, Hints
from CTFd import utils
from CTFd.utils.migrations import upgrade
from CTFd.utils.user import get_ip
from CTFd.utils.uploads import upload_file, delete_file
from CTFd.utils.modes import get_model
from flask import Blueprint
import math

class CTFdKeyedChallenge(BaseChallenge):
    id = "keyed"
    name = "keyed"

def load(app):
    app.db.create_all()
    KEY_CLASSES['keyed'] = OnlineKey
    CHALLENGE_CLASSES['keyed'] = OnlineTypeChallenge
