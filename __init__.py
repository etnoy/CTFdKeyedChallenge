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

class KeyedValueChallenge(BaseChallenge):
    id = "keyed"
    name = "keyed"
    templates = {  # Handlebars templates used for each aspect of challenge editing & viewing
                 'create': '/plugins/keyed_challenges/assets/create.html',
                 'update': '/plugins/keyed_challenges/assets/update.html',
                 'view': '/plugins/keyed_challenges/assets/view.html',
                 }
    scripts = {  # Scripts that are loaded when a template is loaded
               'create': '/plugins/keyed_challenges/assets/create.js',
               'update': '/plugins/keyed_challenges/assets/update.js',
               'view': '/plugins/keyed_challenges/assets/view.js',
               }
    # Route at which files are accessible. This must be registered using register_plugin_assets_directory()
    route = '/plugins/keyed_challenges/assets/'
    # Blueprint used to access the static_folder directory.
    blueprint = Blueprint('keyed_challenges', __name__, template_folder='templates', static_folder='assets')

    @staticmethod
    def create(request):
        """
        This method is used to process the challenge creation request.
        """
        data = request.form or request.get_json()
        challenge = KeyedChallenge(**data)

        db.session.add(challenge)
        db.session.commit()

        return challenge

    @staticmethod
    def read(challenge):
        """
        This method is in used to access the data of a challenge in a format processable by the front end.
        """
        challenge = KeyedChallenge.query.filter_by(id=challenge.id).first()
        data = {
            'id': challenge.id,
            'name': challenge.name,
            'value': challenge.value,
            'initial': challenge.initial,
            'decay': challenge.decay,
            'minimum': challenge.minimum,
            'description': challenge.description,
            'category': challenge.category,
            'state': challenge.state,
            'max_attempts': challenge.max_attempts,
            'type': challenge.type,
            'type_data': {
                'id': KeyedValueChallenge.id,
                'name': KeyedValueChallenge.name,
                'templates': KeyedValueChallenge.templates,
                'scripts': KeyedValueChallenge.scripts,
            }
        }
        return data

    @staticmethod
    def update(challenge, request):
        """
        This method is used to update the information associated with a challenge. This should be kept strictly to the
        Challenges table and any child tables.
        """
        data = request.form or request.get_json()

        for attr, value in data.items():
            # We need to set these to floats so that the next operations don't operate on strings
            if attr in ('initial', 'minimum', 'decay'):
                value = float(value)
                setattr(challenge, attr, value)

        Model = get_model()

        solve_count = Solves.query \
            .join(Model, Solves.account_id == Model.id) \
            .filter(Solves.challenge_id == challenge.id, Model.hidden == False, Model.banned == False) \
            .count()

        challenge.value = challenge.initial

        db.session.commit()
        return challenge

    @staticmethod
    def delete(challenge):
        """
        This method is used to delete the resources used by a challenge.
        """
        Fails.query.filter_by(challenge_id=challenge.id).delete()
        Solves.query.filter_by(challenge_id=challenge.id).delete()
        Flags.query.filter_by(challenge_id=challenge.id).delete()
        files = ChallengeFiles.query.filter_by(challenge_id=challenge.id).all()
        for f in files:
            delete_file(f.id)
            ChallengeFiles.query.filter_by(challenge_id=challenge.id).delete()
            Tags.query.filter_by(challenge_id=challenge.id).delete()
            Hints.query.filter_by(challenge_id=challenge.id).delete()
            KeyedChallenge.query.filter_by(id=challenge.id).delete()
            Challenges.query.filter_by(id=challenge.id).delete()
            db.session.commit()

    @staticmethod
    def attempt(challenge, request):
        data = request.form or request.get_json()
        submission = data['submission'].strip()
        flags = Flags.query.filter_by(challenge_id=challenge.id).all()
        for flag in flags:
            if get_flag_class(flag.type).compare(flag, submission):
                return True, 'Correct'
        return False, 'Incorrect'

    @staticmethod
    def solve(user, team, challenge, request):
        chal = KeyedChallenge.query.filter_by(id=challenge.id).first()
        data = request.form or request.get_json()
        submission = data['submission'].strip()

        Model = get_model()

        solve_count = Solves.query \
            .join(Model, Solves.account_id == Model.id) \
            .filter(Solves.challenge_id == challenge.id, Model.hidden == False, Model.banned == False) \
            .count()

        # It is important that this calculation takes into account floats.
        # Hence this file uses from __future__ import division
        value = (
            (
                (chal.minimum - chal.initial) / (chal.decay**2)
            ) * (solve_count**2)
        ) + chal.initial

        value = math.ceil(value)

        if value < chal.minimum:
            value = chal.minimum

        chal.value = value

        solve = Solves(
            user_id=user.id,
            team_id=team.id if team else None,
            challenge_id=challenge.id,
            ip=get_ip(req=request),
            provided=submission
        )
        db.session.add(solve)
        db.session.commit()
        db.session.close()

    @staticmethod
    def fail(user, team, challenge, request):
        data = request.form or request.get_json()
        submission = data['submission'].strip()
        wrong = Fails(
            user_id=user.id,
            team_id=team.id if team else None,
            challenge_id=challenge.id,
            ip=get_ip(request),
            provided=submission
        )
        db.session.add(wrong)
        db.session.commit()
        db.session.close()

class KeyedChallenge(Challenges):
    __mapper_args__ = {'polymorphic_identity': 'keyed'}
    id = db.Column(None, db.ForeignKey('challenges.id'), primary_key=True)
    initial = db.Column(db.Integer, default=0)
    minimum = db.Column(db.Integer, default=0)
    decay = db.Column(db.Integer, default=0)

    def __init__(self, *args, **kwargs):
        super(KeyedChallenge, self).__init__(**kwargs)
        self.initial = kwargs['value']



def load(app):
    app.db.create_all()
