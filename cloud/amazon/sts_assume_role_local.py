#!/usr/bin/python
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

DOCUMENTATION = '''
---
module: sts_assume_role_local
short_description: Assume a role using AWS Security Token Service and obtain temporary credentials re-use the credential if is still valid
description:
    - Assume a role using AWS Security Token Service and obtain temporary credentials and re-use the credential if is still valid
version_added: "2.0"
author: Giulio Calzolari
options:
  role_arn:
    description:
      - The Amazon Resource Name (ARN) of the role that the caller is assuming (http://docs.aws.amazon.com/IAM/latest/UserGuide/Using_Identifiers.html#Identifiers_ARNs)
    required: true
  role_session_name: 
    description:
      - SessionName
    required: True
    default: null

notes:
  - In order to use the assumed role in a following playbook task you must pass the access_key, access_secret and access_token
extends_documentation_fragment:
    - aws
    - ec2
'''

RETURN = """
sts_creds:
    description: The Credentials object returned by the AWS STS
    returned: always
    type: list
    sample:
      AccessKeyId: XXXXXXXXXXXXXXXXXX
      SessionToken: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      session_token: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
sts_user:
    description: Name of the assumed RoleArn
    returned: always
    type: string
changed:
    description: True if obtaining the credentials succeeds
    type: bool
    returned: always
"""

EXAMPLES = '''
# Note: These examples do not set authentication details, see the AWS Guide for details.

# Assume an existing role (more details: http://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html)

sts_assume_role_local:
  role_arn: "arn:aws:iam::123456789012:role/someRole"
  role_session_name: "SessionName"
  region: "eu-central-1"
register: assumed_role

# Use the assumed role above to tag an instance in account 123456789012
ec2_tag:
  aws_access_key: "{{ assumed_role.sts_creds.AccessKeyId }}"
  aws_secret_key: "{{ assumed_role.sts_creds.SecretAccessKey }}"
  security_token: "{{ assumed_role.sts_creds.SessionToken }}"
  resource: i-xyzxyz01
  state: present
  tags:
    MyNewTag: value

'''

try:
    import boto3
    import botocore
    import os
    import re
    import datetime
    import logging.config
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False



def main():
    argument_spec = ec2_argument_spec()
    argument_spec.update(
        dict(
            role_arn = dict(required=True, default=None),
            role_session_name = dict(required=True, default=None),
            duration_seconds = dict(required=False, default=3600, type='int'),
            external_id = dict(required=False, default=None),
            policy = dict(required=False, default=None),
            mfa_serial_number = dict(required=False, default=None),
            mfa_token = dict(required=False, default=None)
        )
    )    

    module = AnsibleModule(argument_spec=argument_spec)

    if not HAS_BOTO3:
        module.fail_json(msg='boto3 required for this module')

    region, ec2_url, aws_connect_params = get_aws_connection_info(module, boto3=True)

    if region:
        try:
          # logging.basicConfig(filename='/tmp/sts.log', level="INFO")
          # log = logging.getLogger('sts')
          role_arn = module.params.get('role_arn','no-role')
          role_session_name = module.params.get('role_session_name','no-role_session_name')

          local_cred = "/tmp/"+re.sub(r'\W+', '', (role_arn + "_" + role_session_name) ) + ".json"
          
          if os.path.exists(local_cred):
            # log.info("Local cred found: "+local_cred)
            with open(local_cred) as data_file:    
              sts_local = json.load(data_file)

            present = datetime.datetime.utcnow() 
            try:
              d1 = datetime.datetime.strptime(sts_local["Expiration"], "%Y-%m-%d %H:%M:%S+00:00") 
              d2 = present + datetime.timedelta(minutes=5)
              # check if the creadential is expired
              if d1 > d2:
                # log.info("Local cred still valid")
                module.exit_json(changed=False, sts_creds=sts_local, sts_user=sts_local.get("AssumedRoleId", "No-AssumedRoleId"))
              else:
                # log.info("Local cred expired")
                os.remove(local_cred)
            except ValueError as e:
              # some error erase the local cred and request a new one
              # log.error("general error on local cred %s" % e )
              os.remove(local_cred)

          # new sts call
          client = boto3.client('sts',region_name=region)
          response = response = client.assume_role(
              RoleArn=role_arn,
              RoleSessionName=role_session_name,
              DurationSeconds=module.params.get('duration_seconds',3600),
          )
          sts = response["Credentials"]

          sts["Expiration"] = str(response["Credentials"]["Expiration"])
          sts["AssumedRoleId"] = response["AssumedRoleUser"]["AssumedRoleId"]

          # save local file
          # log.info("write local file")
          with open(local_cred, 'w') as outfile:
              json.dump(sts, outfile)

          module.exit_json(changed=True, sts_creds=sts, sts_user=sts["AssumedRoleId"])
        except botocore.exceptions.ClientError as e:
            # log.info("boto error")
            module.fail_json(msg=str(e))
    else:
        module.fail_json(msg="region must be specified")


# import module snippets
from ansible.module_utils.basic import *
from ansible.module_utils.ec2 import *

if __name__ == '__main__':
    main()
