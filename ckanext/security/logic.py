from ckan.plugins.toolkit import (
    get_action, chained_action, check_access, get_or_bust, ValidationError)
from ckan.model import User

from ckanext.security.cache.login import LoginThrottle


def security_user_lockout_delete(context, data_dict):
    check_access('security_user_lockout_delete', context, data_dict)
    user_name = get_or_bust(data_dict, 'id')
    if user_name and isinstance(user_name, basestring):
        LoginThrottle(User.by_name(user_name), '').remove_user_lockout()
    else:
        raise ValidationError({'id': 'Invalid user name'})


@chained_action
def user_update(up_func, context, data_dict):
    rval = up_func(context, data_dict)
    # any user change (e.g. password reset) will reset lockout for that user
    get_action('security_user_lockout_delete')(
        dict(context, ignore_auth=True), {'id': rval['name']})
    return rval
