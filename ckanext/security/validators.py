# encoding: utf-8
import six
import string

# (canada fork only): fix fatal errors
# TODO: upstream contrib!!
from ckan import authz, model
from ckan.common import _
from ckan.lib.navl.dictization_functions import Missing, Invalid
from ckan.plugins.toolkit import config, asbool

MIN_LEN_ERROR = 'Your password must be {} characters or longer.'
COMPLEXITY_ERROR = (
    'Your password must consist of at least three of the following character sets: '
    'uppercase characters, lowercase characters, digits, punctuation & special characters.'
)
SAME_USERNAME_PASSWORD_ERROR = 'Your password cannot be the same as your username.'


def user_password_validator(key, data, errors, context):
    value = data[key]

    if isinstance(value, Missing):
        pass  # Already handled in core
    elif not isinstance(value, six.string_types):
        raise Invalid(_('Passwords must be strings.'))
    elif value == '':
        pass  # Already handled in core
    else:
        # (canada fork only): better error messages
        # TODO: upstream contrib??
        min_password_length = int(config.get('ckanext.security.min_password_length', 8))
        nzism_compliant = asbool(config.get('ckanext.security.nzism_compliant_passwords', True))

        username = data.get(('name',), None)
        password_fields = [
            data.get(('password',), None),
            data.get(('password1',), None),
            data.get(('password2',), None),
        ]

        if username in password_fields:
            errors[key].append(_(SAME_USERNAME_PASSWORD_ERROR))

        if len(value) < min_password_length:
            errors[key].append(_(MIN_LEN_ERROR).format(min_password_length))
        if nzism_compliant:
            # NZISM compliant password rules
            rules = [
                any(x.isupper() for x in value),
                any(x.islower() for x in value),
                any(x.isdigit() for x in value),
                any(x in string.punctuation for x in value)
            ]
            if sum(rules) < 3:
                errors[key].append(_(COMPLEXITY_ERROR))


def old_username_validator(key, data, errors, context):
    # Completely prevents changing of user names
    # (canada fork only): fix fatal errors
    # TODO: upstream contrib!!
    # this validator is only used in user_update schema.
    # the user_update action does get_or_bust for id,
    # so there will always be an id at this point.
    # the action would also have checked for the user
    # in the database, so we can assume that is exists
    # at this point.
    uuid = data.get(key[:-1] + ('id',))
    user_obj = model.User.get(uuid)
    data[key] = user_obj.name
    return


def ensure_str(value):
    return six.text_type(value)
