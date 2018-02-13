import logging

from ckan.lib.authenticator import UsernamePasswordAuthenticator
from ckan.lib.cli import MockTranslator
from ckan.model import User

import pylons
from repoze.who.interfaces import IAuthenticator
from webob.request import Request
from zope.interface import implements

from ckanext.security.cache.login import LoginThrottle
from ckanext.security.mailer import notify_lockout


log = logging.getLogger(__name__)


class CKANLoginThrottle(UsernamePasswordAuthenticator):
    implements(IAuthenticator)

    def authenticate(self, environ, identity):
        """A username/password authenticator that throttles login request by IP."""
        try:
            login = identity['login']
        except KeyError:
            return None

        environ['paste.registry'].register(pylons.translator, MockTranslator())

        try:
            remote_addr = Request(environ).headers['X-Forwarded-For']
        except KeyError:
            try:
                remote_addr = environ['REMOTE_ADDR']
            except KeyError:
                log.critical('X-Forwarded-For header/REMOTE_ADDR missing from request.')
                return None
        else:
            remote_addr = remote_addr.split(',')[-1].split(':')[0]

        throttle = LoginThrottle(User.by_name(login), remote_addr)
        if not ('login' in identity and 'password' in identity):
            return None

        # Run through the CKAN auth sequence first, so we can hit the DB
        # in every case and make timing attacks a little more difficult.
        auth_user = super(CKANLoginThrottle, self).authenticate(environ, identity)

        # Check if there is a lock on the remote address/user
        reason = throttle.lockout_reason()
        if reason:
            log.info('Login blocked by brute force protection. %r %r %r %s' % (
                reason, remote_addr, login, 'pw-ok' if auth_user else 'pw-bad'))
            return None

        # If the CKAN authenticator as successfully authenticated the request
        # and the user wasn't locked out above, return the user object.
        if auth_user is not None:
            log.info('Login accepted. %r %r' % (remote_addr, login))
            return auth_user

        log.info('Login failed. %r %r' % (remote_addr, login))

        # Increment the throttle counter if the login failed.
        new_lockouts = throttle.failed_attempt()
        if 'user' in new_lockouts:
            log.info("User now locked out by brute force protection. %r" % login)
            try:
                notify_lockout(throttle.user, remote_addr)
                log.debug("Lockout notification for user %s sent" % login)
            except Exception as exc:
                msg = "Sending lockout notification for %s failed"
                log.exception(msg % login, exc_info=exc)
        if 'address' in new_lockouts:
            log.info("Address now locked out by brute force protection. %r" % remote_addr)


class BeakerMemcachedAuth(object):
    implements(IAuthenticator)

    def authenticate(self, environ, identity):
        # At this stage, the identity has already been validated from the cookie
        # and memcache (use_beaker middleware). We simply return the user id
        # from the identity object if it's there, or None if the user's
        # identity is not verified.
        return identity.get('repoze.who.userid', None)
