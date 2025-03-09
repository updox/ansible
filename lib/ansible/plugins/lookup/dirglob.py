# (c) 2012, Michael DeHaan <michael.dehaan@gmail.com>
# (c) 2017 Ansible Project
# (c) 2020, Estelle Poulin <epoulin@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = """
    lookup: dirglob
    author: Estelle Poulin <epoulin@updox.com>
    version_added: "2.8.5"
    short_description: list files matching a pattern
    description:
        - Matches all directories in a single directory, non-recursively, that match a pattern.
          It calls Python's "glob" library.
    options:
      _terms:
        description: path(s) of directories to read
        required: True
    notes:
      - Patterns are only supported on directories, not files.
      - Matching is against local system files on the Ansible controller.
        To iterate a list of directories on a remote node, use the M(find) module.
      - Returns a string list of paths joined by commas, or an empty list if no directories match. For a 'true list' pass C(wantlist=True) to the lookup.
"""

EXAMPLES = """
- name: List all home directories on the system.
  debug: msg={{ lookup('dirglob', '/home/*') }}

- name: Include all roles in a directory.
  include_role: name={{ item }}
  with_dirglob: "../roles/*"
"""

RETURN = """
  _list:
    description:
      - list of directories
"""

import os
import glob

from ansible.plugins.lookup import LookupBase
from ansible.errors import AnsibleFileNotFound
from ansible.module_utils._text import to_bytes, to_text


class LookupModule(LookupBase):

    def run(self, terms, variables=None, **kwargs):

        ret = []
        for term in terms:
            term_file = os.path.basename(term)
            dwimmed_path = self.find_file_in_search_path(variables, 'files', os.path.dirname(term))
            if dwimmed_path:
                globbed = glob.glob(to_bytes(os.path.join(dwimmed_path, term_file), errors='surrogate_or_strict'))
                ret.extend(to_text(g, errors='surrogate_or_strict') for g in globbed if os.path.isdir(g))
        return ret
