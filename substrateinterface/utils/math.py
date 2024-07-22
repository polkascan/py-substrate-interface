# Python Substrate Interface Library
#
# Copyright 2018-2024 Stichting Polkascan (Polkascan Foundation).
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
#
#  math.py

"""Some simple math-related utility functions not present in the standard
   library.
"""

from math import ceil, log2


def trailing_zeros(value: int) -> int:
    """Returns the number of trailing zeros in the binary representation of
    the given integer.
    """
    num_zeros = 0
    while value & 1 == 0:
        num_zeros += 1
        value >>= 1
    return num_zeros


def next_power_of_two(value: int) -> int:
    """Returns the smallest power of two that is greater than or equal
    to the given integer.
    """
    if value < 0:
        raise ValueError("Negative integers not supported")
    return 1 if value == 0 else 1 << ceil(log2(value))
