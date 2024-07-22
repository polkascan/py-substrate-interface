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
from scalecodec.types import Enum, U32, U128, U64, Array, U8, Struct

GenericRuntimeCallDefinition = Enum()
GenericContractExecResult = Enum()
BlockNumber = U32
Balance = U128
SlotNumber = U64
VrfOutput = Array(U8, 32)
VrfProof = Array(U8, 64)
RawAuraPreDigest = Struct(slot_number=U64)
RawBabePreDigestPrimary = Struct(authority_index=U32, slot_number=SlotNumber, vrf_output=VrfOutput, vrf_proof=VrfProof)
RawBabePreDigestSecondaryPlain = Struct(authority_index=U32, slot_number=SlotNumber)
RawBabePreDigestSecondaryVRF = Struct(authority_index=U32, slot_number=SlotNumber, vrf_output=VrfOutput, vrf_proof=VrfProof)
RawBabePreDigest = Enum(Phantom=None, Primary=RawBabePreDigestPrimary, SecondaryPlain=RawBabePreDigestSecondaryPlain, SecondaryVRF=RawBabePreDigestSecondaryVRF)
