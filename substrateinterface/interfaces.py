# Python Substrate Interface Library
#
# Copyright 2018-2023 Stichting Polkascan (Polkascan Foundation).
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from typing import Callable

from substrateinterface.extensions import Extension
from substrateinterface.exceptions import ExtensionCallNotFound

__all__ = ['ExtensionInterface']


class ExtensionInterface:
    """
    Keeps tracks of active extensions and which calls can be made
    """

    def __init__(self, substrate):
        self.substrate = substrate
        self.extensions = []

    def __len__(self):
        return len(self.extensions)

    def __iter__(self):
        for item in self.extensions:
            yield item

    def __add__(self, other):
        self.register(other)
        return self

    def register(self, extension: Extension):
        """
        Register an extension instance to the registry and calls initialization

        Parameters
        ----------
        extension: Extension

        Returns
        -------

        """
        if not isinstance(extension, Extension):
            raise ValueError("Provided extension is not a subclass of Extension")

        extension.init(self.substrate)

        self.extensions.append(extension)

    def unregister_all(self):
        """
        Unregister all extensions and free used resources and connections

        Returns
        -------

        """
        for extension in self.extensions:
            extension.close()

    def call(self, name: str, *args, **kwargs):
        """
        Tries to call extension function with `name` and provided args and kwargs

        Will raise a `ExtensionCallNotFound` when no method is found in current extensions

        Parameters
        ----------
        name
        args
        kwargs

        Returns
        -------

        """
        return self.get_extension_callable(name)(*args, **kwargs)

    def get_extension_callable(self, name: str) -> Callable:

        for extension in self.extensions:
            if isinstance(extension, Extension):
                if hasattr(extension, name):
                    try:
                        # Call extension that implements functionality
                        self.substrate.debug_message(f"Call '{name}' using extension {extension.__class__.__name__} ...")
                        return getattr(extension, name)
                    except NotImplementedError:
                        pass

        raise ExtensionCallNotFound(f"No extension registered that implements call '{name}'")

    def __getattr__(self, name):
        return self.get_extension_callable(name)
