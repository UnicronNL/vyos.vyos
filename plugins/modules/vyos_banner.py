# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, print_function

__metaclass__ = type

# (c) 2017, Ansible by Red Hat, inc
#
# This file is part of Ansible by Red Hat
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
#


DOCUMENTATION = """
module: vyos_banner
author: Trishna Guha (@trishnaguha)
short_description: Manage multiline banners on VyOS devices
description:
- This will configure both pre-login and post-login banners on remote devices running
  VyOS. It allows playbooks to add or remote banner text from the active running configuration.
version_added: 1.0.0
notes:
- Tested against VyOS 1.3.0 (equuleus).
options:
  host:
    description:
    - The host to connect to.
    required: true
    type: str
  key:
    description:
    - The api secret key used for the connection.
    required: true
    type: str
  port:
    description:
    - The port the hosts listens on for the connection.
    type: int
    default: 443
  banner:
    description:
    - Specifies which banner that should be configured on the remote device.
    required: true
    choices:
    - pre-login
    - post-login
    type: str
  text:
    description:
    - The banner text that should be present in the remote device running configuration.
      This argument accepts a multiline string, with no empty lines. Requires I(state=present).
    type: str
  state:
    description:
    - Specifies whether or not the configuration is present in the current devices
      active running configuration.
    default: present
    type: str
    choices:
    - present
    - absent
  timeout:
    description:
      - The socket level timeout in seconds
    type: int
    default: 30
  validate_certs:
    description:
      - If C(no), SSL certificates will not be validated.
      - This should only set to C(no) used on personally controlled sites using self-signed certificates.
    type: bool
    default: yes
  client_cert:
    description:
      - PEM formatted certificate chain file to be used for SSL client authentication.
      - This file can also include the key as well, and if the key is included, I(client_key) is not required
    type: path
  client_key:
    description:
      - PEM formatted file that contains your private key to be used for SSL client authentication.
      - If I(client_cert) contains both the certificate and key, this option is not required.
    type: path
  ca_path:
    description:
      - PEM formatted file that contains a CA certificate to be used for validation
    type: path
  use_proxy:
    description:
      - If C(no), it will not use a proxy, even if one is defined in an environment variable on the target hosts.
    type: bool
    default: yes
extends_documentation_fragment:
- vyos.vyos.vyos
"""

EXAMPLES = """
- name: configure the pre-login banner
  vyos.vyos.vyos_banner:
    host: vyos.lab.local
    key: '12345'
    validate_certs: False
    banner: pre-login
    text: |
      this is my pre-login banner
      that contains a multiline
      string
    state: present
- name: remove the post-login banner
  vyos.vyos.vyos_banner:
    banner: post-login
    state: absent
"""

RETURN = """
commands:
  description: The list of configuration mode commands to send to the device
  returned: always
  type: list
  sample:
    - banner pre-login
    - this is my pre-login banner
    - that contains a multiline
    - string
"""

import cgi
import json
import sys

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.six import PY2, PY3, iteritems
from ansible.module_utils.six.moves.urllib.parse import urlencode
from ansible.module_utils._text import to_text
from ansible.module_utils.urls import fetch_url

JSON_CANDIDATES = ('text', 'json', 'javascript')
SKIP_KEYS = ('url', 'server', 'status', 'cookies', 'cookies_string', 'date',
             'connection', 'content-type', 'content-length')

def get_config(module, url, key, banner, socket_timeout, ca_path):
    r = {}
    headers = {}
    body_part = {"op": "returnValues",
                 "path": ["system", "login", "banner",
                          banner]
                }
    payload = {'data': json.dumps(body_part),
               'key': key}
    resp, info = fetch_url(module, url, data=urlencode(payload), headers=headers,
                           method='POST', timeout=socket_timeout,
                           ca_path=ca_path)

    try:
        content = resp.read()
    except AttributeError:
        # there was no content, but the error read()
        # may have been stored in the info as 'body'
        content = info.pop('body', '')

    r.update(info)

    return r, content


def check_config(resp, content, text, state):
    uresp = {}
    for key, value in iteritems(resp):
        if key not in SKIP_KEYS:
            ukey = key.replace("-", "_").lower()
            uresp[ukey] = value

    # Default content_encoding to try
    content_encoding = 'utf-8'
    configured = False
    js = False
    if 'content-type' in resp:
        # Handle multiple Content-Type headers
        content_types = []
        for value in resp['content-type'].split(','):
            ct, params = cgi.parse_header(value)
            if ct not in content_types:
                content_types.append(ct)

        u_content = to_text(content, encoding=content_encoding)
        if any(candidate in content_types[0] for candidate in JSON_CANDIDATES):
            try:
                js = json.loads(u_content)
                if state == 'absent' and not js['data']:
                    configured = True
                elif state != 'absent' and js['data'] and js['data'][0] == text:
                    configured = True
            except Exception:
                if PY2:
                    sys.exc_clear()  # Avoid false positive traceback in fail_json() on Python 2

    return uresp, js, configured


def set_config(module, url, key, text, banner, state, socket_timeout, ca_path):
    mode = 'set'
    r = {}
    headers = {}

    if state == 'absent':
        mode = 'delete'

    body_part = {"op": mode,
                 "path": ["system", "login", "banner",
                          banner, text]
                }
    payload = {'data': json.dumps(body_part),
               'key': key}
    resp, info = fetch_url(module, url, data=urlencode(payload), headers=headers,
                           method='POST', timeout=socket_timeout,
                           ca_path=ca_path)

    try:
        content = resp.read()
    except AttributeError:
        # there was no content, but the error read()
        # may have been stored in the info as 'body'
        content = info.pop('body', '')

    r.update(info)

    return r, content


def get_status(module, statuscode, **uresp):
    if statuscode != 200:
        uresp['msg'] = 'Status code was %s and not 200: %s' % (statuscode, uresp.get('msg', ''))
        module.fail_json(**uresp)


def spec_to_commands(configured, state, banner, text):
    commands = list()

    if state == "absent":
        if not configured:
            commands.append(
                "delete system login banner %s" % banner
            )

    elif state == "present":
        if not configured:
            banner_cmd = (
                "set system login banner %s " % banner
            )
            banner_cmd += "'%s'" % text
            commands.append(banner_cmd)

    return commands


def main():
    """main entry point for module execution"""
    argument_spec = dict(
        host=dict(type='str', required=True),
        port=dict(type='int', default=443),
        key=dict(type='str', no_log=True, required=True),
        banner=dict(type='str', choices=['pre-login', 'post-login']),
        text=dict(type='str'),
        state=dict(type='str', default='present', choices=['present', 'absent']),
        timeout=dict(type='int', default=30),
        validate_certs=dict(type='bool', default=True),
        client_cert=dict(type='path', default=None),
        client_key=dict(type='path', default=None),
        ca_path=dict(type='path', default=None),
        use_proxy=dict(type='bool', default=True),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
    )

    host = module.params['host']
    port = module.params['port']
    key = module.params['key']
    banner = module.params['banner']
    state = module.params['state']
    socket_timeout = module.params['timeout']
    ca_path = module.params['ca_path']
    if PY3:
        text = module.params['text'].rstrip().encode('unicode_escape').decode("utf-8")
    else:
        text = module.params['text'].rstrip().encode('string_escape').decode("utf-8")

    url = "https://%s:%i/retrieve" % (host, port)
    resp, content = get_config(module, url, key, banner, socket_timeout, ca_path)
    resp['changed'] = False
    uresp, js, configured = check_config(resp, content, text, state)

    get_status(module, int(resp['status']), **uresp)

    commands = spec_to_commands(configured, state, banner, text)

    if not configured:
        url = "https://%s:%i/configure" % (host, port)
        resp, content = set_config(module, url, key, text, banner, state, socket_timeout, ca_path)
        resp['changed'] = True

        uresp, js, _ = check_config(resp, content, text, state)
        get_status(module, int(resp['status']), **uresp)

    uresp['commands'] = commands

    module.exit_json(**uresp)


if __name__ == "__main__":
    main()
