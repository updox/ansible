# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os
import os.path
import string
import tempfile
from base64 import b64encode, b64decode, urlsafe_b64encode

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    HAVE_CRYPTOGRAPHY = True
except ImportError:
    HAVE_CRYPTOGRAPHY = False

from ansible import constants as C
from ansible.module_utils._text import to_bytes, to_native, to_text
from ansible.errors import AnsibleActionFail
from ansible.plugins.action import ActionBase
from ansible.utils.encrypt import random_password

def _gen_candidate_chars(characters):
    '''Generate a string containing all valid chars as defined by ``characters``

    :arg characters: A list of character specs. The character specs are
        shorthand names for sets of characters like 'digits', 'ascii_letters',
        or 'punctuation' or a string to be included verbatim.

    The values of each char spec can be:

    * a name of an attribute in the 'strings' module ('digits' for example).
      The value of the attribute will be added to the candidate chars.
    * a string of characters. If the string isn't an attribute in 'string'
      module, the string will be directly added to the candidate chars.

    For example::

        characters=['digits', '?|']``

    will match ``string.digits`` and add all ascii digits.  ``'?|'`` will add
    the question mark and pipe characters directly. Return will be the string::

        u'0123456789?|'
    '''
    chars = []
    for chars_spec in characters:
        # getattr from string expands things like "ascii_letters" and "digits"
        # into a set of characters.
        chars.append(to_text(getattr(string, to_native(chars_spec), chars_spec),
                     errors='strict'))
    chars = u''.join(chars).replace(u'"', u'').replace(u"'", u'')
    return chars

class ActionModule(ActionBase):

    TRANSFERS_FILES = True

    def fernet(self, passphrase, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend())
        key = urlsafe_b64encode(kdf.derive(passphrase))
        return Fernet(key)

    def encrypt(self, passphrase, cleartext):

        # E: data must be bytes
        cleartext = to_bytes(cleartext)

        salt = os.urandom(16)
        ciphertext = self.fernet(passphrase, salt).encrypt(cleartext)
        return [salt, ciphertext]

    def decrypt(self, passphrase, salt, ciphertext):
        return self.fernet(passphrase, salt).decrypt(ciphertext)

    def _pwd_entry_exists(self, path, task_vars):
        stat = self._execute_module(module_name='stat',
                                    module_args=dict(path=path),
                                    task_vars=task_vars)
        if stat.get('failed'):
            raise AnsibleActionFail(stat['msg'])

        return stat['stat']['exists']

    def _pwd_entry_get(self, path, task_vars):
        slurp = self._execute_module(module_name='slurp',
                                     module_args=dict(src=path),
                                     task_vars=task_vars)
        if slurp.get('failed'):
            raise AnsibleActionFail(slurp['msg'])

        secret = b64decode(slurp['content'])
        secret = b64decode(secret)
        salt = secret[0:16]
        ciphertext = secret[16:]
        return [salt, ciphertext]

    def _pwd_entry_set(self, path, salt, ciphertext, task_vars):
        secret = b64encode(salt + ciphertext) + b"\n"
        tmpfile = self._create_content_tempfile(secret)

        tmp_src = self._connection._shell.join_path(
            self._connection._shell.tmpdir, 'source')
        self._transfer_file(tmpfile, tmp_src)
        os.remove(tmpfile)

        copy = self._execute_module(module_name='copy',
                                    module_args=dict(
                                        src=tmp_src,
                                        dest=path,
                                        mode=0o600
                                        # _original_basename=source_rel,
                                        # _copy_mode="single"
                                    ),
                                    task_vars=task_vars)
        if copy.get('failed'):
            raise AnsibleActionFail(copy['msg'])

    def _pwd_entry_remove(self, path, task_vars):
        rm = self._execute_module(module_name='file',
                                  module_args=dict(
                                      path=path,
                                      state='absent'),
                                  task_vars=task_vars)
        if rm.get('failed'):
            raise AnsibleActionFail(rm['msg'])

    def _create_content_tempfile(self, content):
        ''' Create a tempfile containing defined content '''
        fd, content_tempfile = tempfile.mkstemp(dir=C.DEFAULT_LOCAL_TMP)
        f = os.fdopen(fd, 'wb')
        content = to_bytes(content)
        try:
            f.write(content)
        except Exception as err:
            os.remove(content_tempfile)
            raise Exception(err)
        finally:
            f.close()
        return content_tempfile

    def _remove_tempfile_if_content_defined(self, content, content_tempfile):
        if content is not None:
            os.remove(content_tempfile)

    def _mkdir(self, path, task_vars):
        if path == '/':
            return

        stat = self._execute_module(module_name='stat',
                                    module_args=dict(path=path),
                                    task_vars=task_vars)
        if stat.get('failed'):
            raise AnsibleActionFail(stat['msg'])

        if not stat['stat']['exists']:
            parent = os.path.dirname(path)
            self._mkdir(parent, task_vars)

            mkdir = self._execute_module(module_name='file',
                                         module_args=dict(
                                             path=path,
                                             state='directory'),
                                         task_vars=task_vars)
            if mkdir.get('failed'):
                raise AnsibleActionFail(mkdir['msg'])

    def _mkdirs(self, path, task_vars):
        path = path.rstrip('/')
        parent = os.path.dirname(path)
        self._mkdir(parent, task_vars)

        mkdir = self._execute_module(module_name='file',
                                     module_args=dict(
                                         path=path,
                                         mode=0o700,
                                         state='directory'),
                                     task_vars=task_vars)
        if mkdir.get('failed'):
            raise AnsibleActionFail(mkdir['msg'])

    def run(self, tmp=None, task_vars=None):
        result = super(ActionModule, self).run(tmp, task_vars)

        if not HAVE_CRYPTOGRAPHY:
            raise AnsibleActionFail('the cryptography module is not installed')

        key = self._task.args.get('key', task_vars['password_key'])
        name = self._task.args.get('name')
        state = self._task.args.get('state', 'present')
        directory = self._task.args.get('directory', task_vars['password_directory'])
        length = int(self._task.args.get('length', 16))

        # E: Key material must be bytes
        key = to_bytes(key)

    # params['chars'] = params.get('chars', None)
    # if params['chars']:
    #     tmp_chars = []
    #     if u',,' in params['chars']:
    #         tmp_chars.append(u',')
    #     tmp_chars.extend(c for c in params['chars'].replace(u',,', u',').split(u',') if c)
    #     params['chars'] = tmp_chars
    # else:
    #     # Default chars for password
    #     params['chars'] = [u'ascii_letters', u'digits', u".,:-_"]

        # chars = self._task.args.get('chars', 'ascii_letters,digits')
        chars = _gen_candidate_chars([u'ascii_letters', u'digits', u".,:-_"])

        path = os.path.join(directory, name)

        if state == 'present':
            if self._pwd_entry_exists(path, task_vars):
                salt, ciphertext = self._pwd_entry_get(path, task_vars)
                cleartext = self.decrypt(key, salt, ciphertext)

                result['changed'] = False
                result['value'] = cleartext

            else:
                cleartext = random_password(length=length, chars=chars)
                salt, ciphertext = self.encrypt(key, cleartext)

                if not self._play_context.check_mode:
                    self._mkdirs(directory, task_vars)
                    self._pwd_entry_set(path, salt, ciphertext, task_vars)

                result['changed'] = True
                result['value'] = cleartext

        elif state == 'absent':
            if self._pwd_entry_exists(path, task_vars):
                if not self._play_context.check_mode:
                    self._pwd_entry_remove(path, task_vars)

                result['changed'] = True
            else:
                result['changed'] = False

        return result
