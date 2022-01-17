#!/usr/bin/python
#
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
#
from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
module: vyos_config
author: Nathaniel Case (@Qalthos)
short_description: Manage VyOS configuration on remote device
description:
- This module provides configuration file management of VyOS devices. It provides
  arguments for managing both the configuration file and state of the active configuration.
  All configuration statements are based on `set` and `delete` commands in the device
  configuration.
version_added: 1.0.0
extends_documentation_fragment:
- vyos.vyos.vyos
notes:
- Tested against VyOS 1.3.0 (equuleus).
- To ensure idempotency and correct diff the configuration lines in the relevant module options should be similar to how they
  appear if present in the running configuration on device including the indentation.
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
  lines:
    description:
    - The ordered set of commands that should be configured in the section. The commands
      must be the exact same commands as found in the device running-config as found in the
      device running-config to ensure idempotency and correct diff. Be sure
      to note the configuration command syntax as some commands are automatically
      modified by the device config parser.
    type: list
    elements: str
  src:
    description:
    - The C(src) argument specifies the path to the source config file to load.  The
      source config file can either be in bracket format or set format.  The source
      file can include Jinja2 template variables. The configuration lines in the source
      file should be similar to how it will appear if present in the running-configuration
      of the device including indentation to ensure idempotency and correct diff.
    type: path
  match:
    description:
    - The C(match) argument controls the method used to match against the current
      active configuration.  By default, the desired config is matched against the
      active config and the deltas are loaded.  If the C(match) argument is set to
      C(none) the active configuration is ignored and the configuration is always
      loaded.
    type: str
    default: line
    choices:
    - line
    - none
  backup:
    description:
    - The C(backup) argument will backup the current devices active configuration
      to the Ansible control host prior to making any changes. If the C(backup_options)
      value is not given, the backup file will be located in the backup folder in
      the playbook root directory or role root directory, if playbook is part of an
      ansible role. If the directory does not exist, it is created.
    type: bool
    default: no
  config:
    description:
    - The C(config) argument specifies the base configuration to use to compare against
      the desired configuration.  If this value is not specified, the module will
      automatically retrieve the current active configuration from the remote device.
      The configuration lines in the option value should be similar to how it
      will appear if present in the running-configuration of the device including indentation
      to ensure idempotency and correct diff.
    type: str
  backup_options:
    description:
    - This is a dict object containing configurable options related to backup file
      path. The value of this option is read only when C(backup) is set to I(yes),
      if C(backup) is set to I(no) this option will be silently ignored.
    suboptions:
      filename:
        description:
        - The filename to be used to store the backup configuration. If the filename
          is not given it will be generated based on the hostname, current time and
          date in format defined by <hostname>_config.<current-date>@<current-time>
        type: str
      dir_path:
        description:
        - This option provides the path ending with directory name in which the backup
          configuration file will be stored. If the directory does not exist it will
          be first created and the filename is either the value of C(filename) or
          default filename as described in C(filename) options description. If the
          path value is not given in that case a I(backup) directory will be created
          in the current working directory and backup configuration will be copied
          in C(filename) within I(backup) directory.
        type: path
    type: dict
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
"""

EXAMPLES = """
- name: configure the remote device
  vyos.vyos.vyos_config:
    lines:
    - set system host-name {{ inventory_hostname }}
    - set service lldp
    - delete service dhcp-server

- name: backup and load from file
  vyos.vyos.vyos_config:
    src: vyos.cfg
    backup: yes

- name: render a Jinja2 template onto the VyOS router
  vyos.vyos.vyos_config:
    src: vyos_template.j2

- name: for idempotency, use full-form commands
  vyos.vyos.vyos_config:
    lines:
      # - set int eth eth2 description 'OUTSIDE'
    - set interface ethernet eth2 description 'OUTSIDE'

- name: configurable backup path
  vyos.vyos.vyos_config:
    backup: yes
    backup_options:
      filename: backup.cfg
      dir_path: /home/user
"""

RETURN = """
commands:
  description: The list of configuration commands sent to the device
  returned: always
  type: list
  sample: ['...', '...']
filtered:
  description: The list of configuration commands removed to avoid a load failure
  returned: always
  type: list
  sample: ['...', '...']
backup_path:
  description: The full path to the backup file
  returned: when backup is yes
  type: str
  sample: /playbooks/ansible/backup/vyos_config.2016-07-16@22:28:34
filename:
  description: The name of the backup file
  returned: when backup is yes and filename is not specified in backup options
  type: str
  sample: vyos_config.2016-07-16@22:28:34
shortname:
  description: The full path to the backup file excluding the timestamp
  returned: when backup is yes and filename is not specified in backup options
  type: str
  sample: /playbooks/ansible/backup/vyos_config
date:
  description: The date extracted from the backup file name
  returned: when backup is yes
  type: str
  sample: "2016-07-16"
time:
  description: The time extracted from the backup file name
  returned: when backup is yes
  type: str
  sample: "22:28:34"
"""
import re

from ansible.module_utils._text import to_text
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.vyos import (
    get_config,
    run_api_commands,
    get_diff,
)
from ansible_collections.vyos.vyos.plugins.module_utils.network.vyos.vyos import (
    vyos_argument_spec,
)


CONFIG_FILTERS = [
    re.compile(r"set system login user \S+ authentication encrypted-password")
]


def get_candidate(module):
    contents = module.params["src"] or module.params["lines"]

    if module.params["src"]:
        contents = contents.splitlines()
        if len(contents) > 0:
            line = contents[0].split()
            if len(line) > 0 and line[0] in ("set", "delete"):
                contents = format_commands(contents)

    contents = "\n".join(contents)
    return contents


def format_commands(commands):
    """
    This function format the input commands and removes the prepend white spaces
    for command lines having 'set' or 'delete' and it skips empty lines.
    :param commands:
    :return: list of commands
    """
    return [
        line.strip() if line.split()[0] in ("set", "delete") else line
        for line in commands
        if len(line.strip()) > 0
    ]


def diff_config(commands, config):
    config = [str(c).replace("'", "") for c in config.splitlines()]

    updates = list()
    visited = set()

    for linu in commands:
        item = str(line).replace("'", "")

        if not item.startswith("set") and not item.startswith("delete"):
            raise ValueError("line must start with either `set` or `delete`")

        elif item.startswith("set") and item not in config:
            updates.append(line)

        elif item.startswith("delete"):
            if not config:
                updates.append(line)
            else:
                item = re.sub(r"delete", "set", item)
                for entry in config:
                    if entry.startswith(item) and line not in visited:
                        updates.append(line)
                        visited.add(line)

    return list(updates)


def sanitize_config(config, result):
    result["filtered"] = list()
    index_to_filter = list()
    for regex in CONFIG_FILTERS:
        for index, line in enumerate(list(config)):
            if regex.search(line):
                result["filtered"].append(line)
                index_to_filter.append(index)
    # Delete all filtered configs
    for filter_index in sorted(index_to_filter, reverse=True):
        del config[filter_index]


def run(module, result, direct_fail=True):
    # get the current active config from the node or passed in via
    # the config param
    config = module.params["config"] or get_config(module)

    # create the candidate config object from the arguments
    candidate = get_candidate(module)

    # create loadable config that includes only the configuration updates
    try:
        response = get_diff(
            candidate=candidate,
            running=config,
            diff_match=module.params["match"],
        )
    except ConnectionError as exc:
        module.fail_json(msg=to_text(exc, errors="surrogate_then_replace"))

    commands = response.get("config_diff")
    sanitize_config(commands, result)

    result["commands"] = commands

    diff = None
    if commands:
        diff = run_api_commands(module, commands, direct_fail)

        if result.get("filtered"):
            result["warnings"].append(
                "Some configuration commands were "
                "removed, please see the filtered key"
            )

        result["changed"] = True

    if module._diff:
        result["diff"] = {"prepared": diff}


def main():
    backup_spec = dict(filename=dict(), dir_path=dict(type="path"))
    argument_spec = dict(
        host=dict(type='str', required=True),
        port=dict(type='int', default=443),
        key=dict(type='str', no_log=True),
        timeout=dict(type='int', default=30),
        validate_certs=dict(type='bool', default=True),
        client_cert=dict(type='path', default=None),
        client_key=dict(type='path', default=None),
        ca_path=dict(type='path', default=None),
        use_proxy=dict(type='bool', default=True),
        src=dict(type="path"),
        lines=dict(type="list", elements="str"),
        match=dict(default="line", choices=["line", "none"]),
        config=dict(),
        backup=dict(type="bool", default=False),
        backup_options=dict(type="dict", options=backup_spec),
    )

    argument_spec.update(vyos_argument_spec)

    mutually_exclusive = [("lines", "src")]

    module = AnsibleModule(
        argument_spec=argument_spec,
        mutually_exclusive=mutually_exclusive,
        supports_check_mode=False,
    )

    warnings = list()

    result = dict(changed=False, warnings=warnings)

    if module.params["backup"]:
        result["__backup__"] = get_config(module=module)

    if any((module.params["src"], module.params["lines"])):
        run(module, result)

    if result.get("changed") and any(
        (module.params["src"], module.params["lines"])):
        msg = (
            "To ensure idempotency and correct diff the input configuration lines should be"
            " similar to how they appear if present in"
            " the running configuration on device"
        )
        if module.params["src"]:
            msg += " including the indentation"
        if "warnings" in result:
            result["warnings"].append(msg)
        else:
            result["warnings"] = msg

    module.exit_json(**result)


if __name__ == "__main__":
    main()
