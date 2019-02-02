"""Shell Integration class."""
from __future__ import unicode_literals

import os
import shutil
import subprocess

from aws_lp.utils import tempdir


class Shell(object):
    """Shell Integration class."""

    def __init__(self):
        self.env = os.environ.copy()

    def update_env(self, **kwargs):
        """Update environment with new or updated variables."""
        self.env.update(kwargs)

    def handoff(self, prompt_message=''):
        """Handoff to shell process with defined environment.

        Currently only supports bash and zsh with a default of bash.
        """
        if os.name == 'nt':
            bash = shutil.which('bash')

            if bash:
                return subprocess.call(bash, env=self.env)

            return subprocess.call('cmd.exe', env=self.env)

        if 'zsh' in self.env.get('SHELL'):
            return self.handoff_zsh(prompt_message)

        return self.handoff_bash(prompt_message)

    def handoff_bash(self, prompt_message):
        """Handoff to bash with defined environment."""
        if prompt_message:
            bashrc_updates = \
                '''
                PS1="\\[\\e[\\33m\\]({prompt_message})\\[\\e[0m\\] $PS1"
                '''.format(prompt_message=prompt_message)
        else:
            bashrc_updates = ''

        with tempdir('.bashrc', bashrc_updates) as dirpath:
            return subprocess.call('bash --rcfile ' + dirpath + '/.bashrc',
                                   env=self.env, executable='bash')

    def handoff_zsh(self, prompt_message):
        """Handoff to zsh with defined environment."""
        if prompt_message:
            zshrc_updates = \
                '''
                setopt PROMPT_SUBST
                PROMPT="%F{{yellow}}({prompt_message})%f $PROMPT"
                '''.format(prompt_message=prompt_message)
        else:
            zshrc_updates = ''

        with tempdir('.zshrc', zshrc_updates) as dirpath:
            self.update_env(ZDOTDIR=dirpath)

            return subprocess.call('zsh', env=self.env, executable='zsh')
