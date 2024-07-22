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
from typing import Union

from hashlib import blake2b

from scalecodec.base import ScaleType, ScaleTypeDef, ScaleBytes
from scalecodec.constants import TYPE_DECOMP_MAX_RECURSIVE
from scalecodec.exceptions import ScaleEncodeException
from scalecodec.types import HashDef, Vec, U16, Enum, Compact, Bytes, Array, U8, U32
from substrateinterface.utils.ss58 import ss58_encode, ss58_decode, ss58_decode_account_index, is_valid_ss58_address


class GenericAccountId(ScaleType):

    def __init__(self, type_def: ScaleTypeDef, ss58_format=None):
        if ss58_format is None:
            ss58_format = 42
        self.ss58_format = ss58_format
        self.ss58_address = None
        self.public_key = None
        super().__init__(type_def)

    def encode(self, value: any = None) -> ScaleBytes:

        if value is not None and issubclass(self.__class__, value.__class__):
            # Accept instance of current class directly
            self._data = value.data
            self.value_object = value.value_object
            self.value_serialized = value.value_serialized
            return value.data

        if value is None:
            value = self.value_serialized

        if type(value) is bytes:
            value = f'0x{value.hex()}'

        if type(value) is str:
            if value[0:2] == '0x':
                self.public_key = value
                self.ss58_address = ss58_encode(value, ss58_format=self.ss58_format)
            else:

                self.ss58_address = value
                self.public_key = f'0x{ss58_decode(value)}'

        return super().encode(self.public_key)

    def decode(self, data: ScaleBytes, check_remaining=False) -> any:
        value = super().decode(data)
        self.public_key = f'0x{self.value_object.hex()}'
        return value

    def serialize(self) -> str:
        if self.ss58_format is None:
            ss58_format = 42
        else:
            ss58_format = self.ss58_format

        try:
            self.ss58_address = ss58_encode(self.value_object, ss58_format=ss58_format)
            return self.ss58_address
        except ValueError:
            return super().serialize()

    def deserialize(self, value_serialized: any):
        value_object = super().deserialize(value_serialized)
        self.public_key = f'0x{self.value_object.hex()}'

        return value_object


class AccountId(HashDef):

    def __init__(self, *args, ss58_format=None):
        self.ss58_format = ss58_format
        super().__init__(256)

    def new(self, ss58_format=None) -> GenericAccountId:
        if ss58_format is None:
            ss58_format = self.ss58_format
        return GenericAccountId(type_def=self, ss58_format=ss58_format)

    def _encode(self, value: any) -> ScaleBytes:
        if type(value) is str and value[0:2] != '0x':

            value = f'0x{ss58_decode(value)}'

        return super()._encode(value)

    def deserialize(self, value: str) -> bytes:
        if type(value) is str and value[0:2] != '0x':
            value = f'0x{ss58_decode(value)}'

        return super().deserialize(value)

    def example_value(self, _recursion_level: int = 0, max_recursion: int = TYPE_DECOMP_MAX_RECURSIVE):
        return '5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY'


class GenericMultiAccountId(GenericAccountId):
    def __init__(self, type_def: ScaleTypeDef, ss58_format=None,
                 signatories: list = None, threshold: int = None):
        self.ss58_format = ss58_format
        self.ss58_address = None
        self.public_key = None
        self.signatories = signatories
        self.threshold = threshold
        super().__init__(type_def, ss58_format=ss58_format)


class MultiAccountId(AccountId):

    def __init__(self, signatories: list, threshold: int, ss58_format=None):
        self.signatories = signatories
        self.threshold = threshold
        super().__init__(ss58_format=ss58_format)

    def new(self, ss58_format=None) -> GenericMultiAccountId:
        if ss58_format is None:
            ss58_format = self.ss58_format

        multi_account_id = GenericMultiAccountId(
            type_def=self, ss58_format=ss58_format, signatories=self.signatories, threshold=self.threshold
        )

        signatories = sorted([s.public_key for s in self.signatories])

        account_list = Vec(AccountId(ss58_format=ss58_format)).new()
        account_list.encode(signatories)
        threshold_data = U16.encode(self.threshold, external_call=False)

        multi_account_id_data = blake2b(
            b"modlpy/utilisuba" + bytes(account_list.encode(signatories).data) + bytes(threshold_data.data), digest_size=32
        ).digest()

        multi_account_id.encode(multi_account_id_data)

        return multi_account_id


class GenericMultiAddress(ScaleType):
    pass


class MultiAddress(Enum):

    def __init__(self, ss58_format: int = None, **kwargs):
        self.ss58_format = ss58_format
        super().__init__(
            Id=AccountId(ss58_format=ss58_format),
            Index=Compact(),
            Raw=Bytes,
            Address32=Array(U8, 32),
            Address20=Array(U8, 20)
        )

    def new(self) -> GenericMultiAddress:
        return GenericMultiAddress(type_def=self)

    def set_ss58_format(self, ss58_format: int):
        self.ss58_format = ss58_format
        self.variants['Id'] = AccountId(ss58_format=ss58_format)

    def _encode(self, value: Union[str, dict]) -> ScaleBytes:
        if type(value) is int:
            # Implied decoded AccountIndex
            value = {"Index": value}

        elif type(value) is str:
            if len(value) <= 8 and value[0:2] != '0x':
                # Implied raw AccountIndex
                value = {"Index": ss58_decode_account_index(value)}
            elif is_valid_ss58_address(value):
                # Implied SS58 encoded AccountId
                value = {"Id": f'0x{ss58_decode(value)}'}
            elif len(value) == 66 and value[0:2] == '0x':
                # Implied raw AccountId
                value = {"Id": value}
            elif len(value) == 42:
                # Implied raw Address20
                value = {"Address20": value}
            else:
                raise ScaleEncodeException("Address type not yet supported")

        return super()._encode(value)

    def deserialize(self, value: Union[str, dict]) -> tuple:
        if type(value) is int:
            # Implied decoded AccountIndex
            value = {"Index": value}

        elif type(value) is str:
            if len(value) <= 8 and value[0:2] != '0x':
                # Implied raw AccountIndex
                value = {"Index": ss58_decode_account_index(value)}
            elif is_valid_ss58_address(value):
                # Implied SS58 encoded AccountId
                value = {"Id": f'0x{ss58_decode(value)}'}
            elif len(value) == 66 and value[0:2] == '0x':
                # Implied raw AccountId
                value = {"Id": value}
            elif len(value) == 42:
                # Implied raw Address20
                value = {"Address20": value}
            else:
                raise ValueError("Address type not yet supported")

        return super().deserialize(value)


Address = MultiAddress
Index = U32

# AccountId = AccountIdDef()
# MultiAddress = MultiAddressEnum()
