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
from hashlib import blake2b

from typing import Optional, Union

from scalecodec.base import ScaleType, ScaleBytes, ScaleTypeDef
from scalecodec.constants import TYPE_DECOMP_MAX_RECURSIVE
from scalecodec.exceptions import ScaleDecodeException, ScaleEncodeException
from scalecodec.types import EnumType, Enum, Struct, Bytes, Tuple, Array, U8, H512, U64, Compact, U32, Hash
from substrateinterface.constants import DEFAULT_EXTRINSIC_VERSION, BIT_SIGNED, BIT_UNSIGNED, UNMASK_VERSION
from substrateinterface.scale.account import Address, Index
from substrateinterface.scale.types import Balance
from substrateinterface.utils.math import trailing_zeros, next_power_of_two


class GenericCall(EnumType):
    @property
    def call_hash(self):
        return f'0x{blake2b(self._data.data, digest_size=32).digest().hex()}'


class Call(Enum):
    scale_type_cls = GenericCall

    def __init__(self, **kwargs):
        self.metadata = None
        super().__init__(**kwargs)

    def new(self, **kwargs) -> GenericCall:
        # return self.scale_type_cls(type_def=self, metadata=self.metadata)
        kwargs['metadata'] = self.metadata
        return self.scale_type_cls(type_def=self, **kwargs)


class GenericEventRecord(ScaleType):

    @property
    def extrinsic_idx(self) -> Optional[int]:
        if self.value and 'ApplyExtrinsic' in self.value['phase']:
            return self.value['phase']['ApplyExtrinsic']

    @property
    def pallet_name(self):
        return self.value_object['event'][0]

    @property
    def event_name(self):
        return self.value_object['event'][1][0]

    @property
    def attributes(self):
        return self.value_object['event'][1][1]


class ExtrinsicV4Def(Struct):

    @classmethod
    def create_from_metadata(cls, metadata: 'GenericMetadataVersioned'):
        # Process signed extensions in metadata
        signed_extensions = metadata.get_signed_extensions()

        variants = {
            'address': metadata.get_address_type_def(),
            'signature': metadata.get_extrinsic_signature_type_def()
        }

        if len(signed_extensions) > 0:

            if 'CheckMortality' in signed_extensions:
                variants['era'] = signed_extensions['CheckMortality']['extrinsic']

            if 'CheckEra' in signed_extensions:
                variants['era'] = signed_extensions['CheckEra']['extrinsic']

            if 'CheckNonce' in signed_extensions:
                variants['nonce'] = signed_extensions['CheckNonce']['extrinsic']

            if 'ChargeTransactionPayment' in signed_extensions:
                variants['tip'] = signed_extensions['ChargeTransactionPayment']['extrinsic']

            if 'ChargeAssetTxPayment' in signed_extensions:
                variants['asset_id'] = signed_extensions['ChargeAssetTxPayment']['extrinsic']

            if 'CheckMetadataHash' in signed_extensions:
                variants['metadata_check'] = signed_extensions['CheckMetadataHash']['extrinsic']

        variants['call'] = metadata.get_call_type_def()

        return cls(**variants)


class InherentDef(Struct):

    @classmethod
    def create_from_metadata(cls, metadata: 'GenericMetadataVersioned'):
        variants = {'call': metadata.get_call_type_def()}
        return cls(**variants)


class Extrinsic(Struct):

    def __init__(self, metadata: 'GenericMetadataVersioned', **kwargs):
        super().__init__(**kwargs)
        self.scale_type_cls = GenericExtrinsic
        self.metadata = metadata
        self.versions = None

    def new(self, **kwargs) -> 'ScaleType':
        # return self.scale_type_cls(type_def=self, metadata=self.metadata)
        return self.scale_type_cls(type_def=self, metadata=self.metadata, **kwargs)

    def get_signed_extrinsic_def(self, extrinsic_version: int):
        if not self.versions:
            from substrateinterface.scale.metadata import TypeNotSupported
            self.versions = (
                TypeNotSupported("ExtrinsicV1"),
                TypeNotSupported("ExtrinsicV2"),
                TypeNotSupported("ExtrinsicV3"),
                ExtrinsicV4Def.create_from_metadata(metadata=self.metadata),
            )
        return self.versions[extrinsic_version - 1]

    def get_unsigned_extrinsic_def(self, extrinsic_version: int):
        return InherentDef.create_from_metadata(self.metadata)

    # TODO encode must return ScaleType object?
    def _encode(self, value) -> ScaleBytes:

        if 'address' in value and 'signature' in value:
            data = ScaleBytes(bytes([DEFAULT_EXTRINSIC_VERSION | BIT_SIGNED]))
            extrinsic_def = self.get_signed_extrinsic_def(DEFAULT_EXTRINSIC_VERSION)
        else:
            data = ScaleBytes(bytes([DEFAULT_EXTRINSIC_VERSION | BIT_UNSIGNED]))
            extrinsic_def = self.get_unsigned_extrinsic_def(DEFAULT_EXTRINSIC_VERSION)

        self.arguments = extrinsic_def.arguments

        data += extrinsic_def.new().encode(value)

        # Wrap payload as a Bytes
        data = Bytes.new().encode(data.data)

        return data

    def decode(self, data: ScaleBytes) -> dict:
        # Unwrap data
        data = ScaleBytes(Bytes.decode(data))

        # Get extrinsic version information encoding in the first byte
        version_info = int.from_bytes(data.get_next_bytes(1), byteorder='little')

        signed = (version_info & BIT_SIGNED) == BIT_SIGNED
        version = version_info & UNMASK_VERSION

        if signed:
            extrinsic_def = self.get_signed_extrinsic_def(version)
        else:
            extrinsic_def = self.get_unsigned_extrinsic_def(version)

        self.arguments = extrinsic_def.arguments

        return extrinsic_def.decode(data)

    def example_value(self, _recursion_level: int = 0, max_recursion: int = TYPE_DECOMP_MAX_RECURSIVE):
        return '<Extrinsic>'


class GenericExtrinsic(ScaleType):
    @property
    def extrinsic_hash(self):
        if self.data is not None:
            return blake2b(self.data.data, digest_size=32).digest()


class GenericEra(EnumType):

    def __init__(self, type_def: ScaleTypeDef):
        self.period = None
        self.phase = None
        super().__init__(type_def)

    def decode(self, data: ScaleBytes, check_remaining=False) -> dict:

        self._data = data
        self._data_start_offset = data.offset

        enum_byte = data.get_next_bytes(1)
        if enum_byte == b'\x00':
            self.value_serialized = 'Immortal'
        else:

            encoded = int(enum_byte.hex(), base=16) + (int(data.get_next_bytes(1).hex(), base=16) << 8)
            self.period = 2 << (encoded % (1 << 4))
            quantize_factor = max(1, (self.period >> 12))
            self.phase = (encoded >> 4) * quantize_factor
            if self.period >= 4 and self.phase < self.period:

                self.value_serialized = {'Mortal': (self.period, self.phase)}
            else:
                raise ScaleDecodeException('Invalid phase and period: {}, {}'.format(self.phase, self.period))

        self.value_object = self.deserialize(self.value_serialized)

        self._data_end_offset = data.offset

        return self.value_serialized

    def _tuple_from_dict(self, value):
        if 'period' not in value:
            raise ScaleEncodeException("Value missing required field 'period' in dict Era")
        period = value['period']

        if 'phase' in value:
            return (period, value['phase'])

        # If phase not specified explicitly, let the user specify the current block,
        # and calculate the phase from that.
        if 'current' not in value:
            raise ScaleEncodeException("Dict Era must have one of the fields 'phase' or 'current'")

        current = value['current']

        # Period must be a power of two between 4 and 2**16
        period = max(4, min(1 << 16, next_power_of_two(period)))
        phase = current % period
        quantize_factor = max(1, (period >> 12))
        quantized_phase = (phase // quantize_factor) * quantize_factor

        return (period, quantized_phase)

    def encode(self, value: Union[str, dict, ScaleType] = None) -> ScaleBytes:

        if value and issubclass(self.__class__, value.__class__):
            # Accept instance of current class directly
            self._data = value.data
            self.value_object = value.value_object
            self.value_serialized = value.value_serialized
            return value.data

        if value is None:
            value = self.value_serialized

        if type(value) is dict:
            value = value.copy()

        self.value_serialized = value

        if value == 'Immortal':
            self.period = None
            self.phase = None
            self._data = ScaleBytes('0x00')
        elif type(value) is dict:
            if 'Mortal' not in value and 'Immortal' not in value:
                value = {'Mortal': value}
            if type(value['Mortal']) is dict:
                value['Mortal'] = self._tuple_from_dict(value['Mortal'])

            period, phase = value['Mortal']
            if not isinstance(phase, int) or not isinstance(period, int):
                raise ScaleEncodeException("Phase and period must be ints")
            if phase > period:
                raise ScaleEncodeException("Phase must be less than period")
            self.period = period
            self.phase = phase
            quantize_factor = max(period >> 12, 1)
            encoded = min(15, max(1, trailing_zeros(period) - 1)) | ((phase // quantize_factor) << 4)
            self._data = ScaleBytes(encoded.to_bytes(length=2, byteorder='little', signed=False))
        else:
            raise ScaleEncodeException("Incorrect value for Era")

        self._data_start_offset = self._data.offset
        self._data_end_offset = self._data.length

        return self._data

    def is_immortal(self) -> bool:
        """Returns true if the era is immortal, false if mortal."""
        return self.period is None or self.phase is None

    def birth(self, current: int) -> int:
        """Gets the block number of the start of the era given, with `current`
        as the reference block number for the era, normally included as part
        of the transaction.
        """
        if self.is_immortal():
            return 0
        return (max(current, self.phase) - self.phase) // self.period * self.period + self.phase

    def death(self, current: int) -> int:
        """Gets the block number of the first block at which the era has ended.

        If the era is immortal, 2**64 - 1 (the maximum unsigned 64-bit integer) is returned.
        """
        if self.is_immortal():
            return 2**64 - 1
        return self.birth(current) + self.period

    def deserialize(self, value_serialized: any):
        if type(value_serialized) is dict and type(value_serialized['Mortal']) is dict:
            value_serialized['Mortal'] = self._tuple_from_dict(value_serialized['Mortal'])
        return super().deserialize(value_serialized)

class Era(Enum):

    def __init__(self, *args, **kwargs):
        super().__init__(Immortal=None, Mortal=Tuple(Period, Phase))
        self.scale_type_cls = GenericEra


EcdsaSignature = Array(U8, 65)
Ed25519Signature = H512
Sr25519Signature = H512
MultiSignature = Enum(Ed25519=Ed25519Signature, Sr25519=Sr25519Signature, Ecdsa=EcdsaSignature)
ExtrinsicSignature = MultiSignature
Period = U64
Phase = U64
# Era = Enum(Immortal=None, Mortal=Tuple(Period, Phase)).impl(GenericEra)
ExtrinsicV4 = Struct(address=Address, signature=ExtrinsicSignature, era=Era, nonce=Compact(Index), tip=Compact(Balance), call=Call)

Inherent = Struct(call=Call)
# Signature = H512

# AnySignature = H512


ExtrinsicPayloadValue = Struct(call=Call, era=Era, nonce=Compact(Index), tip=Compact(Balance), spec_version=U32, transaction_version=U32, genesis_hash=Hash, block_hash=Hash)
#
# WeightV1 = U64
# WeightV2 = Struct(ref_time=Compact(U64), proof_size=Compact(U64))
# Weight = WeightV2 # TODO
# ContractExecResultTo267 = Struct(gas_consumed=Weight, gas_required=Weight, storage_deposit=StorageDeposit, debug_message=Bytes, result=ContractExecResultResult)
# ContractExecResultTo269 = Struct(gas_consumed=Weight, gas_required=Weight, storage_deposit=StorageDeposit, debug_message=Bytes, result=ContractExecResultResult, events=Option(Vec(frame_system::eventrecord)))
# ContractExecResultResult = Enum(Ok=ContractExecResultOk, Error=sp_runtime::dispatcherror)
# ContractExecResultOk = Struct(flags=ContractCallFlags, data=Bytes)
# ContractExecResultTo260 = Enum(Success=ContractExecResultSuccessTo260, Error=None)
# ContractExecResultSuccessTo260 = Struct(flags=U32, data=Bytes, gas_consumed=U64)
# ContractExecResult = ContractExecResultTo267
# RuntimeCallDefinition = Struct(api=String, method=String, description=String, params=Vec(RuntimeCallDefinitionParam), type=String)
# RuntimeCallDefinitionParam = Struct(name=String, type=String)
