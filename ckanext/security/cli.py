# -*- coding: utf-8 -*-

from __future__ import print_function
import click

from ckanext.security.model import db_setup, SecurityTOTP


def get_commands():
    return [security]


@click.group(short_help="Commands for managing the security module.")
def security():
    pass


@security.command()
def migrate():
    """
    Create the database table to support Time-based One Time Password login
    """
    print("Migrating database for security")
    db_setup()
    print("finished tables setup for security")


@security.command()
@click.argument('username')
def reset_totp(username):
    """
    Generate a new totp secret for a given user
    """
    print('Resetting totp secret for user {}'.format(username))
    SecurityTOTP.create_for_user(username)
    print('Success!')


# (canada fork only): adds capability to show totp setup
@security.command()
@click.argument('username')
def show_totp(username):
    """
    Shows totp setup for a given user
    """
    totp = SecurityTOTP.get_for_user(username)
    if totp:
        click.echo(str(totp.secret))
        return
    click.echo('No TOTP configured for user {}'.format(username))


# (canada fork only): adds capability to delete totp setup
@security.command()
@click.argument('username')
def delete_totp(username):
    """
    Deletes totp setup for a given user
    """
    totp = SecurityTOTP.get_for_user(username)
    if totp:
        click.echo('Deleting TOTP setup for user {}'.format(username))
        deleted = SecurityTOTP.delete_for_user(username)
        if deleted:
            click.echo('Success! Deleted %s rows.' % deleted)
        else:
            click.echo('Error! Deleted 0 rows.')
        return
    click.echo('No TOTP configured for user {}'.format(username))
