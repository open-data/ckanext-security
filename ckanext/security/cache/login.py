import json
import logging
import time

from ckan.common import config

from ckanext.security.cache.clients import MemcachedThrottleClient

BUCKETS_PER_TIMEOUT = 4

log = logging.getLogger(__name__)


class LoginThrottle(object):
    user_lock_timeout = int(config.get('ckanext.security.user_lock_timeout', 60 * 15))
    user_max_failures = int(config.get('ckanext.security.user_max_failures', 10))
    address_lock_timeout = int(config.get('ckanext.security.address_lock_timeout', 60 * 60 * 5))
    address_max_failures = int(config.get('ckanext.security.address_login_max_count', 20))

    def __init__(self, user, remote_addr):
        self.request_time = time.time()
        self.user_bucket = int(
            self.request_time * BUCKETS_PER_TIMEOUT / self.user_lock_timeout)
        self.address_bucket = int(
            self.request_time * BUCKETS_PER_TIMEOUT / self.address_lock_timeout)
        self.user = user
        self.cli = MemcachedThrottleClient()
        self.remote_addr = remote_addr

        # Separately caching user name, because str(user) yields an unwieldy
        # repr of the User class.
        self.user_name = str(user) if user is None else user.name

    def lockout_reason(self):
        """
        Returns:
          'address' if the remote address is locked out
          'user' if this user account is locked out
          None if neither are currently locked out
        """
        lu = 'lu:' + self.user_name
        la = 'la:' + self.remote_addr

        results = self.cli.get_multi([lu, la])
        if la in results and self.request_time < int(results[la]):
            return 'address'
        if lu in results and self.request_time < int(results[lu]):
            return 'user'

    def failed_attempt(self):
        """
        Record a failed login attempt against the address and username counters.

        Returns a set including:
        'user' if the user owning the account is now locked out (and was not before)
        'address' if the remote address is now locked out (and was not before)
        """
        ub = live_buckets('u:' + self.user_name, self.user_bucket)
        ab = live_buckets('a:' + self.remote_addr, self.address_bucket)
        lu = 'lu:' + self.user_name
        la = 'la:' + self.remote_addr

        results = self.cli.get_multi(ub + ab + [lu, la])

        self.cli.set(ub[0], int(results.get(ub[0], 0)) + 1,
            self.user_lock_timeout
            * (BUCKETS_PER_TIMEOUT + 1) / BUCKETS_PER_TIMEOUT)
        self.cli.set(ab[0], int(results.get(ab[0], 0)) + 1,
            self.address_lock_timeout
            * (BUCKETS_PER_TIMEOUT + 1) / BUCKETS_PER_TIMEOUT)

        address_locked = la in results and self.request_time < int(results[la])
        user_locked = lu in results and self.request_time < int(results[lu])
        address_failures = sum(int(results.get(b, 0)) for b in ab) + 1
        user_failures = sum(int(results.get(b, 0)) for b in ub) + 1

        new_locks = set()
        if not address_locked and address_failures >= self.address_max_failures:
            new_locks.add('address')
            self.cli.set(la, int(self.request_time + self.address_lock_timeout),
                self.address_lock_timeout)
        if not user_locked and user_failures >= self.user_max_failures:
            new_locks.add('user')
            self.cli.set(lu, int(self.request_time + self.user_lock_timeout),
                self.user_lock_timeout)
        return new_locks


def live_buckets(key, current_bucket):
    "return keys of live buckets to pass to get_multi"
    return [key + ":" + str(b) for b in
        range(current_bucket, current_bucket - BUCKETS_PER_TIMEOUT - 1, -1)]
