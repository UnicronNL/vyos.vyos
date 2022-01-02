# This code is part of Ansible, but is an independent component.
# This particular file snippet, and this file snippet only, is BSD licensed.
# Modules you write using this snippet, which is embedded dynamically by Ansible
# still belong to the author of the module, and may assign their own license
# to the complete work.
#
# (c) 2016 Red Hat Inc.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
#    * Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright notice,
#      this list of conditions and the following disclaimer in the documentation
#      and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
# USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
from __future__ import absolute_import, division, print_function

__metaclass__ = type
import cgi
import json
import sys

from ansible.module_utils._text import to_text
from ansible.module_utils.basic import env_fallback
from ansible.module_utils.connection import Connection, ConnectionError
from ansible.module_utils.six import PY2
from ansible.module_utils.six.moves.urllib.parse import urlencode
from ansible.module_utils.common._collections_compat import Mapping
from ansible.module_utils.urls import fetch_url

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    to_list,
)

JSON_CANDIDATES = ('text', 'json', 'javascript')
_DEVICE_CONFIGS = {}

vyos_provider_spec = {
    "host": dict(),
    "port": dict(type="int"),
    "username": dict(fallback=(env_fallback, ["ANSIBLE_NET_USERNAME"])),
    "password": dict(
        fallback=(env_fallback, ["ANSIBLE_NET_PASSWORD"]), no_log=True
    ),
    "ssh_keyfile": dict(
        fallback=(env_fallback, ["ANSIBLE_NET_SSH_KEYFILE"]), type="path"
    ),
    "timeout": dict(type="int"),
}
vyos_argument_spec = {
    "provider": dict(
        type="dict",
        options=vyos_provider_spec,
        removed_at_date="2022-06-01",
        removed_from_collection="vyos.vyos",
    )
}


def get_provider_argspec():
    return vyos_provider_spec


def get_connection(module):
    if hasattr(module, "_vyos_connection"):
        return module._vyos_connection

    capabilities = get_capabilities(module)
    network_api = capabilities.get("network_api")
    if network_api == "cliconf":
        module._vyos_connection = Connection(module._socket_path)
    else:
        module.fail_json(msg="Invalid connection type %s" % network_api)

    return module._vyos_connection


def get_capabilities(module):
    if hasattr(module, "_vyos_capabilities"):
        return module._vyos_capabilities

    try:
        capabilities = Connection(module._socket_path).get_capabilities()
    except ConnectionError as exc:
        module.fail_json(msg=to_text(exc, errors="surrogate_then_replace"))

    module._vyos_capabilities = json.loads(capabilities)
    return module._vyos_capabilities


def get_config(module, flags=None, format=None):
    flags = [] if flags is None else flags
    global _DEVICE_CONFIGS

    if _DEVICE_CONFIGS != {}:
        return _DEVICE_CONFIGS
    else:
        connection = get_connection(module)
        try:
            out = connection.get_config(flags=flags, format=format)
        except ConnectionError as exc:
            module.fail_json(msg=to_text(exc, errors="surrogate_then_replace"))
        cfg = to_text(out, errors="surrogate_then_replace").strip()
        _DEVICE_CONFIGS = cfg
        return cfg

def api_command(module, mode, cmd):
    host = module.params['host']
    port = module.params['port']
    key = module.params['key']
    socket_timeout = module.params['timeout']
    ca_path = module.params['ca_path']
    CONFIG_MODE = ('set', 'delete', 'comment')

    if mode in CONFIG_MODE:
        uri = 'configure'
    else:
        uri = mode

    url = "https://%s:%i/%s" % (host, port, uri)
    r = {}
    body_part = {"op": mode, "path": cmd['command']}
    payload = {'data': json.dumps(body_part),
               'key': key}
    resp, info = fetch_url(module, url, data=urlencode(payload), headers={},
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

def parse_commands(module, resp, content):
    uresp = {}
    content_encoding = 'utf-8'

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
                uresp['json'] = js
                if int(resp['status']) not in (200, 400):
                    msg = uresp['json']['error']
                    module.fail_json(msg)
            except Exception:
                if PY2:
                    sys.exc_clear()  # Avoid false positive traceback in fail_json() on Python 2
    else:
        module.fail_json(resp['msg'])

    return uresp

def run_api_commands(module, commands=None):
    if commands is None:
        raise ValueError("'commands' value is required")

    responses = list()
    for cmd in to_list(commands):
        if not isinstance(cmd, Mapping):
            cmd = {"command": cmd.split()}

        mode = cmd['command'].pop(0)
        resp, content = api_command(module, mode, cmd)
        uresp = parse_commands(module, resp, content)
        if uresp['json']['success']:
            if uresp['json']['data']:
                responses.append(uresp['json']['data'])
        else:
            responses.append(uresp['json']['error'])

    return responses


def run_commands(module, commands, check_rc=True):
    connection = get_connection(module)
    try:
        response = connection.run_commands(
            commands=commands, check_rc=check_rc
        )
    except ConnectionError as exc:
        module.fail_json(msg=to_text(exc, errors="surrogate_then_replace"))
    return response


def load_config(module, commands, commit=False, comment=None):
    connection = get_connection(module)

    try:
        response = connection.edit_config(
            candidate=commands, commit=commit, comment=comment
        )
    except ConnectionError as exc:
        module.fail_json(msg=to_text(exc, errors="surrogate_then_replace"))

    return response.get("diff")
