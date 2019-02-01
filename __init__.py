#!/usr/bin/env python
# -*- coding: utf-8 -*-
from CTFd.plugins import register_plugin_assets_directory
from CTFd.plugins.challenges import BaseChallenge, CHALLENGE_CLASSES, CTFdStandardChallenge, get_key_class
from CTFd.models import db, Solves, WrongKeys, Keys, Challenges, Files, Tags, Teams
from CTFd.plugins.keys import BaseKey, KEY_CLASSES
from CTFd.utils import admins_only, is_admin, upload_file, delete_file

from CTFd.config import Config

class KeyedKey(BaseKey):
    name = "keyed"

class CTFdKeyedChallenge(Challenges):
    __mapper_args__ = {'polymorphic_identity': 'keyed'}
    id = db.Column(None, db.ForeignKey('challenges.id'), primary_key=True)
    token = db.Column(db.String(80))

    def __init__(self, name, description, value, category, token, type='keyed'):
        self.name = name
        self.description = description
        self.value = value
        self.category = category
        self.type = type
        self.token = token

def load(app):
    app.db.create_all()
    KEY_CLASSES['keyed'] = OnlineKey
    CHALLENGE_CLASSES['keyed'] = OnlineTypeChallenge
