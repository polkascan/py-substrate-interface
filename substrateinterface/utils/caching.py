# Python Substrate Interface Library
#
# Copyright 2018-2021 Stichting Polkascan (Polkascan Foundation).
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

from functools import lru_cache


def block_dependent_lru_cache(maxsize=10, typed=False, block_arg_index=None):
    def decorator(f):
        cached_func = lru_cache(maxsize=maxsize, typed=typed)(f)

        def wrapper(*args, **kwargs):

            use_cache = False

            if block_arg_index is not None:
                if len(args) > block_arg_index and args[block_arg_index] is not None:
                    use_cache = True

            if kwargs.get('block_hash') is not None or kwargs.get('block_id') is not None:
                use_cache = True

            if use_cache:
                return cached_func(*args, **kwargs)
            else:
                return f(*args, **kwargs)

        return wrapper
    return decorator
