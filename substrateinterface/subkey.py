# Python Substrate Interface
#
# Copyright 2018-2020 openAware BV (NL).
# This file is part of Polkascan.
#
# Polkascan is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Polkascan is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Polkascan. If not, see <http://www.gnu.org/licenses/>.

import json
import shlex
import subprocess
from abc import ABC, abstractmethod

import docker
from docker.errors import ContainerError


class CommandFailException(Exception):
    pass


class InvalidConfigurationError(Exception):
    pass


class SubkeyImplementation(ABC):

    @abstractmethod
    def execute_command(self, command, stdin=None, json_output=True, **kwargs):
        pass

    def generate_key(self, network):
        return self.execute_command(['--network={}'.format(network), 'generate'])

    def sign(self, data, suri, is_hex=True):

        return self.execute_command(
            command=['sign', '--hex', suri],
            stdin=data,
            json_output=False
        )


class DockerSubkeyImplementation(SubkeyImplementation):

    def __init__(self, docker_image=None):

        self.docker_image = docker_image or 'parity/subkey:latest'

    def execute_command(self, command, stdin=None, json_output=True, **kwargs):

        command = ['--output=json'] + command

        full_command = ' '.join([shlex.quote(el) for el in command])

        if stdin:
            full_command = '-c "echo -n \\"{}\\" | subkey {}"'.format(stdin, full_command)
        else:
            full_command = '-c "subkey {}"'.format(full_command)

        client = docker.from_env()
        try:
            output = client.containers.run(self.docker_image, full_command, entrypoint='/bin/sh')

            output = output[0:-1].decode()

            if json_output:
                output = json.loads(output)

            return output

        except ContainerError as e:
            raise CommandFailException('Docker Error: ', e)

        except json.JSONDecodeError as e:
            raise CommandFailException('Invalid format: ', e)


class LocalSubkeyImplementation(SubkeyImplementation):

    def __init__(self, subkey_path=None):
        self.subkey_path = subkey_path

    def execute_command(self, command, stdin=None, json_output=True, **kwargs):

        result = subprocess.run([self.subkey_path, '--output=json'] + command, input=stdin, encoding='ascii',
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        if result.returncode > 0:
            raise CommandFailException(result.stderr)

        # Strip the newline in the end of the result
        output = result.stdout[0:-1]

        if json_output:
            output = json.loads(output)

        return output


class Subkey:

    def __init__(self, use_docker=True, docker_image=None, subkey_path=None):

        if subkey_path:
            self.implementation = LocalSubkeyImplementation(subkey_path=subkey_path)
        elif use_docker:
            self.implementation = DockerSubkeyImplementation(docker_image=docker_image)
        else:
            raise InvalidConfigurationError(
                'No valid subkey configuration, either set subkey_path, subkey_host or subkey_host'
            )

    def execute_command(self, command):
        self.implementation.execute_command(command)

    def generate_key(self, network):
        return self.implementation.generate_key(network=network)

    def sign(self, data, suri, is_hex=True):
        if is_hex:
            data = data.replace('0x', '')
        return self.implementation.sign(data=data, suri=suri, is_hex=is_hex)
