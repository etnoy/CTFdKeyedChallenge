from __future__ import print_function
from CTFd.plugins.challenges import BaseChallenge, CHALLENGE_CLASSES
from CTFd.plugins import register_plugin_assets_directory
from CTFd.utils.user import get_current_team, get_current_user
from CTFd.plugins.flags import get_flag_class, FLAG_CLASSES
from CTFd.models import db, Solves, Fails, Flags, Challenges, ChallengeFiles, Tags, Users, Teams, Hints
from CTFd import utils
from CTFd.utils.migrations import upgrade
from CTFd.utils.user import get_ip
from CTFd.utils.uploads import upload_file, delete_file
from CTFd.utils.modes import get_model
from flask import Blueprint
from flask import render_template
import sys
import nacl.secret
import nacl.utils

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

        box=nacl.secret.SecretBox(nacl.encoding.Base64Encoder.decode(challenge.key))
        salt=nacl.encoding.Base64Encoder.decode(challenge.salt)

        user=get_current_user()
        team=get_current_team()

        user_id=user.id,
        team_id=team.id if team else None,

        flag='U' + str(user_id)+'T'+str(team_id)+'F'+salt

        encrypted_flag='flag(' + nacl.encoding.Base64Encoder.encode(box.encrypt(flag)) + ')'

        data = {
            'id': challenge.id,
            'name': challenge.name,
            'value': challenge.value,
            'description': encrypted_flag,
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
            setattr(challenge, attr, value)

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

        chal = KeyedChallenge.query.filter_by(id=challenge.id).first()

        box=nacl.secret.SecretBox(nacl.encoding.Base64Encoder.decode(chal.key))
        salt=nacl.encoding.Base64Encoder.decode(chal.salt)

        if len(submission) < 7:
            return False, 'Invalid format'

        if submission[:5] != 'flag(':
            return False, 'Invalid format'

        if submission[-1:] != ')':
            return False, 'Invalid format'

        submission=submission[5:-1]

        try:
            flag=nacl.encoding.Base64Encoder.decode(submission)
        except TypeError:
            return False, 'Invalid format'

        try:
            decrypted_flag=box.decrypt(flag)
        except nacl.exceptions.CryptoError:
            # Verification failed
            return False, 'Incorrect decrypt'

        user=get_current_user()
        team=get_current_team()

        user_id=user.id,
        team_id=team.id if team else None,

        stored_flag='U'+str(user_id)+'T'+str(team_id)+'F'+salt
        print(stored_flag,file=sys.stderr)
        print(decrypted_flag,file=sys.stderr)

        if decrypted_flag == stored_flag:
            return True, 'Correct'
        else:
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
    value = db.Column(db.Integer, default=0)
    key = db.Column(db.Text)
    salt = db.Column(db.Text)

    def __init__(self, *args, **kwargs):
        super(KeyedChallenge, self).__init__(**kwargs)
        self.initial = kwargs['value']
        self.key = nacl.encoding.Base64Encoder.encode(nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE))
        self.salt = nacl.encoding.Base64Encoder.encode(nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE))

class UserSalt(db.Model):
    __tablename__ = 'usersalt'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'))
    challenge_id = db.Column(db.Integer, db.ForeignKey('challenges.id', ondelete='CASCADE'))
    salt = db.Column(db.Text, unique=True)

    user = db.relationship("Users", foreign_keys='UserSalt.user_id', lazy='select')#, back_populates="salt")
    challenge = db.relationship("Challenges", foreign_keys='UserSalt.challenge_id', lazy='select')#, back_populates="user_salts")

    def __init__(self, *args, **kwargs):
        super(UserSalt, self).__init__(**kwargs)
        #self.salt = nacl.encoding.HexEncoder.encode(nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE))

def load(app):
    app.db.create_all()
    CHALLENGE_CLASSES['keyed'] = KeyedValueChallenge
    register_plugin_assets_directory(app, base_path='/plugins/keyed_challenges/assets/')
