# -*- coding: utf-8 -*-

import logging

from ckanext.security import utils
from ckan.lib import helpers
from flask import Blueprint, make_response
from functools import wraps
from ckan.plugins import toolkit as tk
# (canada fork only): check access
from ckan import model

log = logging.getLogger(__name__)


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        utils.check_user_and_access()
        return f(*args, **kwargs)
    return decorated_function


mfa_user = Blueprint("mfa_user", __name__)


# (canada fork only): check access
def _fresh_context():
    return {
        'model': model, 'session': model.Session,
        'user': tk.g.user, 'auth_user_obj': tk.g.userobj
    }


def login():
    # (canada fork only): limit to config
    #TODO: upstream contrib??
    if not tk.h.security_enable_totp():
        return tk.abort(404)
    headers = {'Content-Type': 'application/json'}
    (status, res_data) = utils.login()
    return make_response((res_data, status, headers))


@login_required
def configure_mfa(id=None):
    # (canada fork only): limit to config
    #TODO: upstream contrib??
    if not tk.h.security_enable_totp():
        return tk.abort(404)
    # (canada fork only): check access
    try:
        tk.check_access('user_update', _fresh_context(), {'id': id})
    except tk.NotAuthorized:
        tk.abort(403, tk._('Unauthorized to edit a user.'))
    extra_vars = utils.configure_mfa(id)
    return tk.render('security/configure_mfa.html',
                     extra_vars=extra_vars)  # (canada fork only): 2.10 support


@login_required
def new(id=None):
    # (canada fork only): limit to config
    #TODO: upstream contrib??
    if not tk.h.security_enable_totp():
        return tk.abort(404)
    # (canada fork only): check access
    try:
        tk.check_access('user_update', _fresh_context(), {'id': id})
    except tk.NotAuthorized:
        tk.abort(403, tk._('Unauthorized to edit a user.'))
    utils.new(id)
    return helpers.redirect_to('mfa_user.configure_mfa', id=id)


# (canada fork only): disable MFA
@login_required
def disable(id=None):
    # (canada fork only): limit to config
    #TODO: upstream contrib??
    if not tk.h.security_enable_totp():
        return tk.abort(404)
    # (canada fork only): check access
    try:
        tk.check_access('user_update', _fresh_context(), {'id': id})
    except tk.NotAuthorized:
        tk.abort(403, tk._('Unauthorized to edit a user.'))
    utils.disable(id)
    return helpers.redirect_to('mfa_user.configure_mfa', id=id)


mfa_user.add_url_rule('/api/mfa_login', view_func=login, methods=['POST'])
mfa_user.add_url_rule('/configure_mfa/<id>',
                      view_func=configure_mfa, methods=['GET', 'POST'])
mfa_user.add_url_rule('/configure_mfa/<id>/new',
                      view_func=new, methods=['GET', 'POST'])
# (canada fork only): disable MFA
mfa_user.add_url_rule('/configure_mfa/<id>/disable',
                      view_func=disable, methods=['GET', 'POST'])


def get_blueprints():
    return [mfa_user]
