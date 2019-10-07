#!/usr/bin/python
# -*- coding: utf-8 -*-

DOCUMENTATION = """
---
module: password
short_description: Manage a password wallet on the host
description:
  - This module manages a password wallet that is stored on the host that
    is targeted by a play.
author: Michael Franz Aigner
options:
  initial:
    description:
      - The initial value of the password. When C(state=present) and the
        requested password entry is not in the wallet, the entry will be
        created with this password value. Required when C(state=present).
    required: false
  name:
    description:
      - A name to use as key for the entry in the wallet.
    required: true
  state:
    description:
      - Should be C(present) if an entry should be added to or retrieved from
        the wallet, or C(absent) if the entry should be removed from the
        wallet.
    required: false
    choices: [present, absent]
    default: present
  wallet:
    description:
      - The absolute path of a directory to use as password wallet. This
        directory and its parents will be created if needed.
    required: false
    default: /var/lib/ansible/passwords
"""

RETURN = r"""
value: the password retrieved from the wallet, if C(state=present)
"""

EXAMPLES = """
- name: Generate a password for the MySQL root user
  password:
    name: mysql_root
    initial: "{{ lookup('password', '/dev/null') }}"
  register: mysql_root_password

- name: Display the password of the MySQL root user
  debug:
    var: mysql_root_password.value

- name: Remove the password of the MySQL root user from the wallet
  password:
    name: mysql_root
    state: absent
"""
