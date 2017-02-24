# aws-emergency

This script encapsulates some actions that can be taken if you suspect that some of your
access credentials or IAM users have been compromised.

## Warning

This script can be used to restrict activities on your account. It does NOT currently
delete any resources, and its direct effects should be reversible. However, it can also
prevent activity by AWS services, e.g. log storage, CloudFormation actions, etc. and
BREAK your AWS setup.

Be sure to understand what this script does before using it.

## Usage

You need to have python (both 2 or 3 work) with boto3 installed,
as well as AWS credentials which can be picked up by boto3.

The most useful (but also most drastic) action of this tool is to add inline DENY ALL policies
named "EmergencyUserLock-\<random number\>" and "EmergencyRoleLock-\<random number\>"
to both IAM users and roles (except the user which executes this action):

./aws\_emergency.py --lock-all

If you accidentally executed this command for testing and now want to undo this action, do:

./aws\_emergency.py --unlock-all

To lock individual users or roles, use --lock-user \<name\>, --unlock-user \<name\>
and --lock-role \<name\>, --unlock-role \<name\>.
