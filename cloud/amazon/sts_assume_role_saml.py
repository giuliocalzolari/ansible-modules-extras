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
module: sts_assume_role_saml
short_description: Assume a role using AWS Security Token Service and obtain temporary credentials with saml 
description:
    - Assume a role using AWS Security Token Service and obtain temporary credentials using saml authentication on adfs windows 2012
version_added: "2.2"
author: Giulio Calzolari
options:
  role_arn:
    description:
      - The Amazon Resource Name (ARN) of the role that the caller is assuming (http://docs.aws.amazon.com/IAM/latest/UserGuide/Using_Identifiers.html#Identifiers_ARNs)
    required: true
  adfs_url:
    description:
      - ADFs url
    required: True
    default: null
  adfs_username:
    description:
      - adfs_username 
    required: True
    default: null 
  password_file:
    description:
      - password file to be auth on adfs your password need to be stored written in base64 mode 
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
    description: The Credentials object returned by the AWS STS with SAML
    returned: always
    type: list
    sample:
      access_key: XXXXXXXXXXXXXXXXXX
      secret_key: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
      session_token: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
changed:
    description: True if obtaining the credentials succeeds
    type: bool
    returned: always
"""

EXAMPLES = '''
# Note: These examples do not set authentication details, see the AWS Guide for details.

# Assume an existing role (more details: http://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html)

sts_assume_role_saml:
  adfs_url: 'https://adfs.example.com/adfs/ls/idpinitiatedsignon?loginToRp=urn:amazon:webservices' 
  adfs_username: "{{adfs_username}}"
  password_file: ~/.aws/adfs-secret.key
  role_arn: "arn:aws:iam::123456789012:role/someRole"
  region: "eu-central-1"
register: assumed_role

# Use the assumed role above to tag an instance in account 123456789012
ec2_tag:
  aws_access_key: "{{ assumed_role.sts_creds.access_key }}"
  aws_secret_key: "{{ assumed_role.sts_creds.secret_key }}"
  security_token: "{{ assumed_role.sts_creds.session_token }}"
  resource: i-xyzxyz01
  state: present
  tags:
    MyNewTag: value

'''

try:
    import boto3
    import botocore
    import base64
    from bs4 import BeautifulSoup 
    from os.path import expanduser 
    import xml.etree.ElementTree as ET 
    from urlparse import urlparse, urlunparse 
    from requests_ntlm import HttpNtlmAuth
    import requests 
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False



def get_role_from_adfs(module):
  # Initiate session handler 
  session = requests.Session() 

  if "~" in module.params.get('password_file'):
    pass_file = module.params.get('password_file').replace("~",expanduser("~"))
  else:
    pass_file = module.params.get('password_file')
   
  password = open(pass_file, 'r').read()
  # Programatically get the SAML assertion 
  # Set up the NTLM authentication handler by using the provided credential 
  session.auth = HttpNtlmAuth(module.params.get('adfs_username'), base64.b64decode(password),session) 
   
  # Opens the initial AD FS URL and follows all of the HTTP302 redirects 
  #response = session.get(idpentryurl, verify=sslverification) 
  headers = {'User-Agent': 'Mozilla/5.0 (compatible, MSIE 11, "\
          "Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko'}
  response = session.get(module.params.get('adfs_url'), verify=False, headers=headers) 


  # Decode the response and extract the SAML assertion 
  soup = BeautifulSoup(response.text.decode('utf8')) 
  assertion = '' 
   
  # Look for the SAMLResponse attribute of the input tag (determined by 
  # analyzing the debug print lines above) 

  for inputtag in soup.find_all('input'): 
      if(inputtag.get('name') == 'SAMLResponse'): 
          #print(inputtag.get('value')) 
          assertion = inputtag.get('value')

  # Parse the returned assertion and extract the authorized roles 
  awsroles = [] 
  root = ET.fromstring(base64.b64decode(assertion))
   
  for saml2attribute in root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'): 
      if (saml2attribute.get('Name') == 'https://aws.amazon.com/SAML/Attributes/Role'): 
          for saml2attributevalue in saml2attribute.iter('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
              awsroles.append(saml2attributevalue.text) 

  # Note the format of the attribute value should be role_arn,principal_arn 
  # but lots of blogs list it as principal_arn,role_arn so let's reverse 
  # them if needed 
  for awsrole in awsroles: 
      chunks = awsrole.split(',') 
      if'saml-provider' in chunks[0]:
          newawsrole = chunks[1] + ',' + chunks[0] 
          index = awsroles.index(awsrole) 
          awsroles.insert(index, newawsrole) 
          awsroles.remove(awsrole)

  for awsrole in awsroles: 
      if module.params.get('role_arn') in awsrole.split(',')[0]:
        return awsrole.split(',')[0], awsrole.split(',')[1], assertion

  module.fail_json(msg='No role match')


def main():
    argument_spec = ec2_argument_spec()
    argument_spec.update(
        dict(
            adfs_url = dict(required=True, default=None),
            adfs_username = dict(required=True, default=None),
            password_file = dict(required=True, default=None),
            role_arn = dict(required=True, default=None),
        )
    )

    module = AnsibleModule(argument_spec=argument_spec)

    if not HAS_BOTO3:
        module.fail_json(msg='boto3 required for this module')

    region, ec2_url, aws_connect_params = get_aws_connection_info(module, boto3=True)

    if region:
        try:

          role_arn, principal_arn, assertion = get_role_from_adfs(module)
          # Use the assertion to get an AWS STS token using Assume Role with SAML
          client = boto3.client('sts',region_name=region)

          rs = client.assume_role_with_saml(
              RoleArn=role_arn,
              PrincipalArn=principal_arn,
              SAMLAssertion=assertion
          )

          sts = {"access_key": rs["Credentials"]["AccessKeyId"], "secret_key":rs["Credentials"]["SecretAccessKey"]  ,"session_token":rs["Credentials"]["SessionToken"] }

          module.exit_json(changed=True, sts_creds=sts, sts_user=rs["AssumedRoleUser"]["AssumedRoleId"])
        except botocore.exceptions.ClientError as e:
            module.fail_json(msg=str(e))
    else:
        module.fail_json(msg="region must be specified")

   


# import module snippets
from ansible.module_utils.basic import *
from ansible.module_utils.ec2 import *

if __name__ == '__main__':
    main()
