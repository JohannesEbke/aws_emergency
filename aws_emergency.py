#!/usr/bin/env python
# pylint: disable=import-error,invalid-name
"""Module providing emergency shutdown functions"""
from __future__ import print_function

from multiprocessing.pool import ThreadPool
from random import randint
import json

import boto3

LOCK_DOCUMENT_STRING = json.dumps({
    'Version': '2012-10-17',
    'Statement': [{
        'Sid': 'EmergencyLock',
        'Effect': 'Deny',
        'Action': ['*'],
        'Resource': ['*']
    }]
})


def get_all_access_keys():
    """List access keys from all IAM users in this account"""
    iam = boto3.client('iam')
    usernames = [user['UserName'] for user in iam.list_users()['Users']]
    access_keys = sum(ThreadPool(16).imap(
        lambda user: iam.list_access_keys(UserName=user)['AccessKeyMetadata'],
        usernames
    ), [])
    return access_keys


def update_access_key(iam, access_key, enabled):
    """Set the access key described by the given document to either enabled or disabled"""
    params = {
        'AccessKeyId': access_key['AccessKeyId'],
        'Status': 'Active' if enabled else 'Inactive'
    }
    if 'UserName' in access_key:
        params['UserName'] = access_key['UserName']

    iam.update_access_key(**params)

    return '{}abled access key from {} with id {}'.format(
        'En' if enabled else 'Dis',
        access_key.get('UserName', '<root>'),
        access_key['AccessKeyId']
    )


def disable_all_access_keys():
    """Disable the access keys of all IAM users in this account, except the one used currently"""
    access_keys = get_all_access_keys()
    session = boto3.session.Session()
    iam = session.client('iam')

    my_access_key_id = session.get_credentials().access_key
    keys_to_disable = [access_key for access_key in access_keys
                       if access_key['Status'] == 'Active'
                       and access_key['AccessKeyId'] != my_access_key_id]
    def disable(key):
        """Disable this access key"""
        update_access_key(iam, key, enabled=False)
    for output in ThreadPool(16).imap(disable, keys_to_disable):
        print(output)
    for access_key in access_keys:
        if access_key['AccessKeyId'] == my_access_key_id:
            print('Skipped own access key:', access_key['AccessKeyId'])


def enable_all_access_keys():
    """Enable all access keys of all IAM users in this account.

    This also enables access keys that may have already been disabled for other reasons!"""
    access_keys = get_all_access_keys()
    iam = boto3.client('iam')
    for access_key in access_keys:
        if access_key['Status'] == 'Inactive':
            print(update_access_key(iam, access_key, enabled=True))


def lock_user(username):
    """Add an inline user policy to the given user with a DENY ALL rule, denying all activity.

    The affected user can still login, but should not be able do to anything."""
    iam = boto3.client('iam')
    iam.put_user_policy(
        UserName=username,
        PolicyName='EmergencyUserLock-{}'.format(randint(1e12, 9e12)),
        PolicyDocument=LOCK_DOCUMENT_STRING
    )
    return 'Locked user ' + username


def unlock_user(username):
    """Revert the action of lock_user. It does not grant any additional rights"""
    iam = boto3.client('iam')
    policy_names = iam.list_user_policies(UserName=username)['PolicyNames']
    for policy_name in policy_names:
        if policy_name.startswith('EmergencyUserLock-'):
            iam.delete_user_policy(UserName=username, PolicyName=policy_name)
    return 'Unlocked user ' + username


def lock_role(rolename):
    """Add an inline role policy to the given role with a DENY ALL rule, denying all activity.

    The affected role can still be assumed, but should not be able do to anything."""
    iam = boto3.client('iam')
    iam.put_role_policy(
        RoleName=rolename,
        PolicyName='EmergencyRoleLock-{}'.format(randint(1e12, 9e12)),
        PolicyDocument=LOCK_DOCUMENT_STRING
    )
    return 'Locked role ' + rolename


def unlock_role(rolename):
    """Revert the action of lock_role. It does not grant any additional rights"""
    iam = boto3.client('iam')
    policy_names = iam.list_role_policies(RoleName=rolename)['PolicyNames']
    for policy_name in policy_names:
        if policy_name.startswith('EmergencyRoleLock-'):
            iam.delete_role_policy(RoleName=rolename, PolicyName=policy_name)
    return 'Unlocked role ' + rolename


def lock_all():
    """List and lock all IAM users and roles in this account.

    This may affect the operation of AWS services that can assume roles to take action on
    the users behalf, e.g. CloudFormation"""
    iam = boto3.client('iam')
    iam.list_access_keys()
    rolenames = [role['RoleName'] for role in iam.list_roles()['Roles']]
    for output in ThreadPool(16).imap(lock_role, rolenames):
        print(output)
    my_username = iam.get_user()['User'].get('UserName', '<root>')
    usernames = [user['UserName'] for user in iam.list_users()['Users']
                 if user['UserName'] != my_username]
    for output in ThreadPool(16).imap(lock_user, usernames):
        print(output)


def unlock_all():
    """Remove emergency locks from all IAM users and roles in this account."""
    iam = boto3.client('iam')
    usernames = [user['UserName'] for user in iam.list_users()['Users']]
    for output in ThreadPool(16).imap(unlock_user, usernames):
        print(output)
    rolenames = [role['RoleName'] for role in iam.list_roles()['Roles']]
    for output in ThreadPool(16).imap(unlock_role, rolenames):
        print(output)


def main():
    """Parse CLI arguments to either list services, operations, queries or existing pickles"""
    import argparse
    parser = argparse.ArgumentParser(
        description='Emergency shutdown procedures'
    )
    parser.add_argument('--disable-all-access-keys', action='store_true',
                        help='Disable all user access keys')
    parser.add_argument('--enable-all-access-keys', action='store_true',
                        help='Re-enable all user access keys')
    parser.add_argument('--lock-user',
                        help='Prevent the specified user from taking any actions via inline policy')
    parser.add_argument('--unlock-user',
                        help='Remove a previously placed user lock')
    parser.add_argument('--lock-role',
                        help='Prevent the specified role from taking any actions via inline policy')
    parser.add_argument('--unlock-role',
                        help='Remove a previously placed role lock')
    parser.add_argument('--lock-all', action='store_true',
                        help='Locks all users and roles on the account')
    parser.add_argument('--unlock-all', action='store_true',
                        help='Unlocks all users and roles on the account')

    args = parser.parse_args()

    if args.disable_all_access_keys:
        disable_all_access_keys()
    elif args.enable_all_access_keys:
        enable_all_access_keys()
    elif args.lock_user:
        print(lock_user(args.lock_user))
    elif args.unlock_user:
        print(unlock_user(args.unlock_user))
    elif args.lock_role:
        print(lock_role(args.lock_role))
    elif args.unlock_role:
        print(unlock_role(args.unlock_role))
    elif args.lock_all:
        lock_all()
    elif args.unlock_all:
        unlock_all()
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
