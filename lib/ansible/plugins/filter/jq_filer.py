from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible.errors import AnsibleError, AnsibleFilterError
from ansible.module_utils._text import to_native

import json
try:
    import jq
    HAS_JQ = True
except ImportError:
    HAS_JQ = False


def jq_filter(obj, expr, parse=False, *args, **kwargs):
    if not HAS_JQ:
        raise AnsibleError("You must install the jq Python module to use the jq filter.")

    try:
        prog = jq.jq(expr)
    except ValueError as e:
        raise AnsibleFilterError("Error compiling jq expression: %s" % to_native(e))
    except Exception as e:
        raise AnsibleFilterError("Unknown error with jq expression: %s" % to_native(e))

    if not isinstance(obj, str):
        try:
            obj = json.dumps(obj)
        except ValueError as e:
            raise AnsibleFilterError("Could not serialize object as JSON: %s" % to_native(e))

    try:
        return prog.transform(text=obj, *args, **kwargs)
    except Exception as e:
        raise AnsibleFilterError("Error applying JSON expression to data: %s" % to_native(e))

class FilterModule(object):
    def filters(self):
        return {
            'jq': jq_filter,
        }
