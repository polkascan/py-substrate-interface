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
from typing import Optional, Type, List

from scalecodec.base import ScaleTypeDef, ScaleBytes, ScaleType
from scalecodec.constants import TYPE_DECOMP_MAX_RECURSIVE
from scalecodec.types import DataType, U8, U16, U32, U64, U128, U256, I8, I16, I32, I64, I128, I256, Bool, String, \
    Array, Struct, Tuple, Vec, Option, Null, Enum, Compact, BitVec, EnumType, Bytes, Text, BTreeMap
from substrateinterface.scale.account import AccountId, MultiAddress
from substrateinterface.scale.extrinsic import Era, Call, GenericCall, GenericEventRecord, Extrinsic
from substrateinterface.scale.migrations.runtime_calls import get_apis, get_type_def


class TypeNotSupported(ScaleTypeDef):

    def __init__(self, type_string):
        self.type_string = type_string
        super().__init__()

    def new(self):
        raise NotImplementedError(f"Type {self.type_string} not supported")

    def _encode(self, value: any) -> ScaleBytes:
        raise NotImplementedError(f"Type {self.type_string} not supported")

    def decode(self, data: ScaleBytes) -> any:
        raise NotImplementedError(f"Type {self.type_string} not supported")


class GenericRegistryType(ScaleType):

    @property
    def docs(self):
        return self.value['docs']

    def encode(self, value):
        if 'params' not in value:
            value['params'] = []

        if 'path' not in value:
            value['path'] = []

        if 'docs' not in value:
            value['docs'] = []

        return super().encode(value)



class RegistryTypeDef(ScaleTypeDef):

    def __init__(self, portable_registry, si_type_id):
        super().__init__()
        self.portable_registry = portable_registry
        self.si_type_id = si_type_id
        self.__type_def = None

    @property
    def type_def(self) -> ScaleTypeDef:
        if self.__type_def is None:
            self.__type_def = self.portable_registry.create_scale_type_def(self.si_type_id)
            self.scale_type_cls = self.__type_def.scale_type_cls
        return self.__type_def

    def new(self, **kwargs) -> 'ScaleType':
        return self.type_def.scale_type_cls(type_def=self.type_def, **kwargs)

    def _encode(self, value: any) -> ScaleBytes:
        return self.type_def._encode(value)

    def decode(self, data: ScaleBytes) -> any:
        return self.type_def.decode(data)

    def serialize(self, value: any) -> any:
        return self.type_def.serialize(value)

    def deserialize(self, value: any) -> any:
        return self.type_def.deserialize(value)

    def example_value(self, _recursion_level: int = 0, max_recursion: int = TYPE_DECOMP_MAX_RECURSIVE):
        # if _recursion_level <= 2:
        #     return self.type_def.example_value(_recursion_level + 1, max_recursion)
        # else:
        return f'<RegistryTypeDef: {self.si_type_id}>'


class GenericPortableRegistry(ScaleType):

    def __init__(self, type_def: ScaleTypeDef, runtime_config=None):
        super().__init__(type_def)
        self.runtime_config = runtime_config
        self.si_type_registry = {}
        self.path_lookup = {}

        self.__def_overrides = {
            "sp_core::crypto::AccountId32": AccountId,
            'sp_runtime::multiaddress::MultiAddress': MultiAddress,
            'sp_runtime::generic::era::Era': Era,
            'frame_system::extensions::check_mortality::CheckMortality': Era,
            'RuntimeCall': Call
        }

        self.__impl_overrides = {
            'RuntimeCall': GenericCall,
            # 'Call': GenericCall,
            'EventRecord': GenericEventRecord,
            'pallet_identity::types::Data': DataType
        }

        self.__primitive_types = {
            'U8': U8,
            'u8': U8,
            'u16': U16,
            'u32': U32,
            'u64': U64,
            'u128': U128,
            'u256': U256,
            'i8': I8,
            'i16': I16,
            'i32': I32,
            'i64': I64,
            'i128': I128,
            'i256': I256,
            'bool': Bool(),
            'str': String
        }

    def get_registry_type(self, si_type_id: int) -> GenericRegistryType:
        try:
            return self.value_object['types'][si_type_id]['type']
        except IndexError:
            raise ValueError(f"RegistryType not found with id {si_type_id}")

    def get_primitive_type_def(self, type_string: str) -> ScaleTypeDef:
        if type_string not in self.__primitive_types:
            raise ValueError(f"{type_string} is not a valid primitive")
        return self.__primitive_types[type_string]

    def get_scale_type_def(self, si_type_id: int) -> ScaleTypeDef:
        if si_type_id not in self.si_type_registry:
            # Create placeholder to prevent recursion issues
            self.si_type_registry[si_type_id] = RegistryTypeDef(self, si_type_id)
            self.si_type_registry[si_type_id] = self.create_scale_type_def(si_type_id)

        return self.si_type_registry[si_type_id]

    def get_si_type_id(self, path: str) -> int:
        if not self.path_lookup:
            self.path_lookup = {'::'.join(t['type']['path']).lower(): t['id'] for t in self.value_object['types'].value if t['type']['path']}
        si_type_id = self.path_lookup.get(path.lower())

        if si_type_id is None:
            raise ValueError(f"Path '{path}' is not found in portable registry")

        return si_type_id

    def get_type_def_primitive(self, name) -> ScaleTypeDef:
        type_def = self.__primitive_types.get(name.lower())

        if type_def is None:
            raise ValueError(f"Primitive '{name}' not found ")

        return type_def

    def get_type_def_override_for_path(self, path: list) -> Optional[ScaleTypeDef]:
        type_def = self.__def_overrides.get('::'.join(path))
        if type_def is None:
            type_def = self.__def_overrides.get(path[-1])
        return type_def

    def get_impl_override_for_path(self, path: list) -> Optional[Type[ScaleType]]:
        scale_type_cls = self.__impl_overrides.get(path[-1])
        if scale_type_cls is None:
            scale_type_cls = self.__impl_overrides.get('::'.join(path))
        return scale_type_cls

    def create_scale_type_def(self, si_type_id: int) -> ScaleTypeDef:

        registry_type = self.value_object['types'][si_type_id]['type']

        # Check if def override is defined for path
        type_def_override = None
        type_impl_override = None

        if 'path' in registry_type.value and len(registry_type.value['path']) > 0:
            type_def_override = self.get_type_def_override_for_path(registry_type.value['path'])

            type_impl_override = self.get_impl_override_for_path(registry_type.value['path'])

        if "primitive" in registry_type.value["def"]:
            try:
                return self.__primitive_types[registry_type.value["def"]["primitive"]]
            except KeyError:
                raise ValueError(f'Primitive type "{registry_type.value["def"]["primitive"]}" not found')

        elif 'array' in registry_type.value["def"]:

            return Array(
                self.get_scale_type_def(registry_type.value['def']['array']['type']),
                registry_type.value['def']['array']['len']
            )

        elif 'composite' in registry_type.value["def"]:

            fields = registry_type.value["def"]['composite']['fields']

            if all([f.get('name') for f in fields]):

                fields = {field['name']: self.get_scale_type_def(field['type']) for field in fields}
                type_def_cls = type_def_override or Struct
                type_def = type_def_cls(**fields)

            else:
                items = [self.get_scale_type_def(field['type']) for field in fields]
                type_def_cls = type_def_override or Tuple
                type_def = type_def_cls(*items)

            if type_impl_override:
                type_def = type_def.impl(type_impl_override)

            return type_def

        elif 'sequence' in registry_type.value["def"]:
            # Vec
            type_def = self.get_scale_type_def(registry_type.value['def']['sequence']['type'])
            return Vec(type_def)

        elif 'variant' in registry_type.value["def"]:

            if registry_type.value["path"] == ['Option']:
                # Option
                return Option(self.get_scale_type_def(registry_type.value['params'][0]['type']))

            # Enum
            variants_mapping = []

            variants = registry_type.value["def"]['variant']['variants']

            if len(variants) > 0:
                # Create placeholder list
                variant_length = max([v['index'] for v in variants]) + 1
                variants_mapping = [(f'__{i}', Null) for i in range(0, variant_length)]

                for variant in variants:

                    if 'fields' in variant:
                        if len(variant['fields']) == 0:
                            enum_value = None
                        elif all([f.get('name') for f in variant['fields']]):
                            # Enum with named fields
                            fields = {f.get('name'): self.get_scale_type_def(f['type']) for f in variant['fields']}
                            enum_value = Struct(**fields)
                        else:
                            if len(variant['fields']) == 1:
                                enum_value = self.get_scale_type_def(variant['fields'][0]['type'])
                            else:
                                items = [self.get_scale_type_def(f['type']) for f in variant['fields']]
                                enum_value = Tuple(*items)
                    else:
                        enum_value = Null

                    # Put mapping in right order in list
                    variants_mapping[variant['index']] = (variant['name'], enum_value)

            # TODO convert reserved names
            variants_dict = {v[0]: v[1] for v in variants_mapping}

            type_def_cls = type_def_override or Enum

            type_def = type_def_cls(**variants_dict)

            if type_impl_override:
                type_def = type_def.impl(type_impl_override)

            return type_def

        elif 'tuple' in registry_type.value["def"]:

            items = [self.get_scale_type_def(i) for i in registry_type.value["def"]['tuple']]

            type_def_cls = type_def_override or Tuple

            return type_def_cls(*items)

        elif 'compact' in registry_type.value["def"]:
            # Compact
            return Compact(self.get_scale_type_def(registry_type.value["def"]['compact']["type"]))

        elif 'phantom' in registry_type.value["def"]:
            return Null

        elif 'bitsequence' in registry_type.value["def"]:
            return BitVec()

        else:
            raise NotImplementedError(f"RegistryTypeDef {registry_type.value['def']} not implemented")






class GenericMetadataVX(ScaleType):

    def migrate_to_latest(self):
        pass


class GenericMetadataV14(GenericMetadataVX):
    pass


class MetadataAllType(EnumType):
    """
    Enum that contains a Metadata version.

    E.g.  `{"V14": MetadataV14}`
    """

    @property
    def pallets(self):
        metadata_obj = self.value_object[1]
        return metadata_obj.value_object['pallets'].value_object

    @property
    def portable_registry(self):
        return self.value_object[1].value_object['types']

    def get_event(self, pallet_index, event_index):
        pass

    def get_metadata_pallet(self, name: str) -> Optional['PalletMetadataType']:
        for pallet in self[1]['pallets']:
            if pallet.value['name'] == name:
                return pallet


class GenericMetadataVersioned(ScaleType):
    """
    Tuple that contains a backwards compatible MetadataAll type
    """

    def get_module_error(self, module_index, error_index):
        if self.portable_registry:
            for pallet in self.pallets:
                if pallet.value['index'] == module_index:
                    error_enum = self.portable_registry.get_scale_type_def(pallet.value['error']['ty'])
                    return list(error_enum.variants.items())[error_index][0]
        else:
            return self.value_object[1].error_index.get(f'{module_index}-{error_index}')

    def get_metadata(self):
        return self.value_object[1]

    @property
    def portable_registry(self) -> 'PortableRegistry':
        return self.get_metadata().portable_registry

    @property
    def pallets(self):
        return self.get_metadata().pallets

    @property
    def apis(self) -> List['GenericRuntimeApiMetadata']:
        if self.get_metadata().index >= 15:
            return self.get_metadata()[1]['apis'].value_object
        else:
            apis = Vec(RuntimeApiMetadataV14).new()
            apis.encode(get_apis())
            return apis.value_object

    def get_api(self, name: str) -> 'GenericRuntimeApiMetadata':
        for api in self.apis:
            if name == api.value['name']:
                return api
        raise ValueError(f"Runtime Api '{name}' not found")

    def get_metadata_pallet(self, name: str) -> 'PalletMetadataType':
        return self.get_metadata().get_metadata_pallet(name)

    def get_pallet_by_index(self, index: int):

        for pallet in self.pallets:
            if pallet.value['index'] == index:
                return pallet

        raise ValueError(f'Pallet for index "{index}" not found')

    def get_signed_extensions(self) -> dict:

        signed_extensions = {}

        if self.portable_registry:
            for se in self.value_object[1][1]['extrinsic']['signed_extensions'].value:
                signed_extensions[se['identifier']] = {
                    'extrinsic': self.portable_registry.get_scale_type_def(se['ty']),
                    'additional_signed': self.portable_registry.get_scale_type_def(se['additional_signed'])
                }

        return signed_extensions

    def get_call_type_def(self) -> ScaleTypeDef:

        extrinsic_registry_type = self.get_extrinsic_registry_type()
        for param in extrinsic_registry_type.value['params']:
            if param['name'] == 'Call':
                call_def = self.portable_registry.get_scale_type_def(param['type'])
                call_def.metadata = self
                return call_def

    def get_extrinsic_registry_type(self) -> GenericRegistryType:
        si_type_id = self.value_object[1][1]['extrinsic']['ty'].value
        return self.portable_registry.get_registry_type(si_type_id)

    def get_extrinsic_type_def(self) -> ScaleTypeDef:
        return Extrinsic(self)

    def get_address_type_def(self) -> ScaleTypeDef:
        extrinsic_registry_type = self.get_extrinsic_registry_type()
        for param in extrinsic_registry_type.value['params']:
            if param['name'] == 'Address':
                return self.portable_registry.get_scale_type_def(param['type'])

    def get_extrinsic_signature_type_def(self) -> ScaleTypeDef:
        extrinsic_registry_type = self.get_extrinsic_registry_type()
        for param in extrinsic_registry_type.value['params']:
            if param['name'] == 'Signature':
                return self.portable_registry.get_scale_type_def(param['type'])


class PalletMetadataType(ScaleType):

    @property
    def name(self):
        return self.value['name']

    def get_identifier(self):
        return self.value['name']

    @property
    def storage(self) -> Optional[list]:

        storage_functions = self.value_object['storage'].value_object

        if storage_functions:
            pallet_version_sf = StorageEntryMetadataCustom.new()
            pallet_version_sf.encode({
                'name': ':__STORAGE_VERSION__:',
                'modifier': 'Default',
                'type': {'Plain': 'u16'},
                'default': '0x0000',
                'documentation': ['Returns the current pallet version from storage']
            })

            return [pallet_version_sf] + storage_functions['entries'].value_object

    @property
    def calls(self):
        if self.value_object['calls'].value_object:
            return self.value_object['calls'].value_object.calls
        else:
            return []

    @property
    def events(self):
        if self.value_object['event'].value_object:
            return self.value_object['event'].value_object.events
        else:
            return []

    @property
    def errors(self):
        if self.value_object['error'].value_object:
            return self.value_object['error'].value_object.errors
        else:
            return []

    @property
    def constants(self):
        return self.value_object['constants'].value_object

    def get_storage_function(self, name: str):
        if self.storage:

            # Convert name for well-known PalletVersion storage entry
            if name == 'PalletVersion':
                name = ':__STORAGE_VERSION__:'

            for storage_function in self.storage:
                if storage_function.value['name'] == name:
                    return storage_function


class GenericRuntimeApiMetadata(ScaleType):

    @property
    def name(self):
        return self.value['name']

    @property
    def methods(self):
        return list(self.value_object['methods'])

    def get_method(self, name: str) -> 'GenericRuntimeApiMethodMetadata':
        for method in self.methods:
            if name == method.value['name']:
                return method
        raise ValueError(f"Runtime API method '{self.value['name']}.{name}' not found")


class LegacyRuntimeApiMetadata(GenericRuntimeApiMetadata):
    pass


class GenericRuntimeApiMethodMetadata(ScaleType):

    @property
    def name(self):
        return self.value['name']

    def get_params(self, metadata):
        return [
            {
                'name': p['name'],
                'type_def': metadata.portable_registry.get_scale_type_def(p["type"])
            } for p in self.value['inputs']
        ]

    def get_return_type_def(self, metadata):
        return metadata.portable_registry.get_scale_type_def(self.value['output'])


class LegacyRuntimeApiMethodMetadata(GenericRuntimeApiMethodMetadata):

    def get_params(self, metadata):
        return [{'name': p['name'], 'type_def': get_type_def(p["type"], metadata)} for p in self.value['inputs']]

    def get_return_type_def(self, metadata):
        return get_type_def(self.value['output'], metadata)


class GenericEventMetadata(ScaleType):

    @property
    def name(self):
        return self.value['name']

    @property
    def args(self):
        return self.value_object['args']

    @property
    def docs(self):
        return self.value['documentation']


class GenericErrorMetadata(ScaleType):

    @property
    def name(self):
        return self.value['name']

    @property
    def docs(self):
        return self.value['documentation']


class GenericStorageEntryMetadata(ScaleType):

    def get_value_type_id(self):
        if 'Plain' in self.value['type']:
            return self.value['type']['Plain']
        elif 'Map' in self.value['type']:
            return self.value['type']['Map']['value']
        else:
            raise NotImplementedError()

    def get_key_type_id(self):
        if 'Map' in self.value['type']:
            return self.value['type']['Map']['key']

    def get_params_type_id(self) -> Optional[int]:
        if 'Plain' in self.value['type']:
            return None
        elif 'Map' in self.value['type']:
            return self.value['type']['Map']['key']
        else:
            raise NotImplementedError()

    def get_key_scale_info_definition(self):
        if 'Map' in self.value['type']:
            key_type_string = self.get_type_string_for_type(self.value['type']['Map']['key'])
            nmap_key_scale_type = self.runtime_config.get_decoder_class(key_type_string)

            return nmap_key_scale_type.scale_info_type['def'][0]

    def get_param_hashers(self):
        if 'Plain' in self.value['type']:
            return ['Twox64Concat']
        elif 'Map' in self.value['type']:
            return self.value['type']['Map']['hashers']
        else:
            raise NotImplementedError()

    def get_param_info(self, max_recursion: int = TYPE_DECOMP_MAX_RECURSIVE) -> list:
        """
        Return a type decomposition how to format parameters for current storage function

        Returns
        -------
        list
        """
        param_info = []
        for param_type_string in self.get_params_type_string():
            scale_type = self.runtime_config.create_scale_object(param_type_string)
            param_info.append(scale_type.generate_type_decomposition(max_recursion=max_recursion))

        return param_info


SiLookupTypeId = Compact(U32)
StorageHasherV13 = Enum(
    Blake2_128=None, Blake2_256=None, Blake2_128Concat=None, Twox128=None, Twox256=None, Twox64Concat=None,
    Identity=None
)
StorageEntryModifierV13 = Enum(Optional=None, Default=None, Required=None)
MapTypeV14 = Struct(
    hashers=Vec(StorageHasherV13), key=SiLookupTypeId, value=SiLookupTypeId
)
StorageEntryTypeV14 = Enum(Plain=SiLookupTypeId, Map=MapTypeV14)
StorageEntryMetadataV14 = Struct(
    name=String, modifier=StorageEntryModifierV13, type=StorageEntryTypeV14, default=Bytes, documentation=Vec(Text)
).impl(GenericStorageEntryMetadata)
StorageMetadataV14 = Struct(prefix=Text, entries=Vec(StorageEntryMetadataV14))
PalletCallMetadataV14 = Struct(ty=SiLookupTypeId)
FunctionArgumentMetadataV14 = Struct(name=Text, type=SiLookupTypeId)
FunctionMetadataV14 = Struct(name=String, args=Vec(FunctionArgumentMetadataV14), documentation=Vec(String))
PalletEventMetadataV14 = Struct(ty=SiLookupTypeId)
PalletConstantMetadataV14 = Struct(name=String, type=SiLookupTypeId, value=Bytes, documentation=Vec(String))
PalletErrorMetadataV14 = Struct(ty=SiLookupTypeId)

PalletMetadataV14 = Struct(
    name=Text, storage=Option(StorageMetadataV14), calls=Option(PalletCallMetadataV14),
    event=Option(PalletEventMetadataV14), constants=Vec(PalletConstantMetadataV14),
    error=Option(PalletErrorMetadataV14), index=U8
).impl(PalletMetadataType)

StorageEntryTypeCustom = Enum(Plain=String)
StorageEntryMetadataCustom = Struct(
    name=String, modifier=StorageEntryModifierV13, type=StorageEntryTypeCustom, default=Bytes, documentation=Vec(Text)
).impl(GenericStorageEntryMetadata)


SignedExtensionMetadataV14 = Struct(identifier=String, ty=SiLookupTypeId, additional_signed=SiLookupTypeId)
ExtrinsicMetadataV14 = Struct(ty=SiLookupTypeId, version=U8, signed_extensions=Vec(SignedExtensionMetadataV14))
TypeParameter = Struct(name=String, type=Option(SiLookupTypeId))
Field = Struct(name=Option(String), type=SiLookupTypeId, typeName=Option(String), docs=Vec(String))
TypeDefComposite = Struct(fields=Vec(Field))
Variant = Struct(name=String, fields=Vec(Field), index=U8, docs=Vec(String))
TypeDefVariant = Struct(variants=Vec(Variant))
TypeDefSequence = Struct(type=SiLookupTypeId)
TypeDefArray = Struct(len=U32, type=SiLookupTypeId)
TypeDefTuple = Vec(SiLookupTypeId)
TypeDefPrimitive = Enum(
    bool=None, char=None, str=None, U8=None, u16=None, u32=None, u64=None, u128=None, u256=None, i8=None, i16=None,
    i32=None, i64=None, i128=None, i256=None
)
TypeDefCompact = Struct(type=SiLookupTypeId)
TypeDefPhantom = Null
TypeDefBitSequence = Struct(bit_store_type=SiLookupTypeId, bit_order_type=SiLookupTypeId)
TypeDef = Enum(
    composite=TypeDefComposite, variant=TypeDefVariant, sequence=TypeDefSequence, array=TypeDefArray,
    tuple=TypeDefTuple, primitive=TypeDefPrimitive, compact=TypeDefCompact, bitsequence=TypeDefBitSequence
)
RegistryType = Struct(
    path=Vec(String), params=Vec(TypeParameter), def_=TypeDef, docs=Vec(String)
).impl(
    scale_type_cls=GenericRegistryType
)

PortableType = Struct(id=SiLookupTypeId, type=RegistryType)
PortableRegistry = Struct(types=Vec(PortableType)).impl(GenericPortableRegistry)

RuntimeApiMethodParamMetadataV14 = Struct(name=Text, type=String)

RuntimeApiMethodMetadataV14 = Struct(
    name=Text, inputs=Vec(RuntimeApiMethodParamMetadataV14), output=String, docs=Vec(Text)
).impl(LegacyRuntimeApiMethodMetadata)

RuntimeApiMetadataV14 = Struct(
    name=Text, methods=Vec(RuntimeApiMethodMetadataV14), docs=Vec(Text)
).impl(GenericRuntimeApiMetadata)


MetadataV14 = Struct(
    types=PortableRegistry, pallets=Vec(PalletMetadataV14), extrinsic=ExtrinsicMetadataV14, runtime_type=SiLookupTypeId
).impl(GenericMetadataV14)

PalletMetadataV15 = Struct(
    name=Text,
    storage=Option(StorageMetadataV14),
    calls=Option(PalletCallMetadataV14),
    event=Option(PalletEventMetadataV14),
    constants=Vec(PalletConstantMetadataV14),
    error=Option(PalletErrorMetadataV14),
    index=U8,
    docs=Vec(Text)
).impl(PalletMetadataType)

ExtrinsicMetadataV15 = Struct(
    version=U8,
    address_type=SiLookupTypeId,
    call_type=SiLookupTypeId,
    signature_type=SiLookupTypeId,
    extra_type=SiLookupTypeId,
    signed_extensions=Vec(SignedExtensionMetadataV14)
)
OuterEnums15 = Struct(call_type=SiLookupTypeId, event_type=SiLookupTypeId, error_type=SiLookupTypeId)
CustomValueMetadata15 = Bytes
CustomMetadata15 = BTreeMap(Text, CustomValueMetadata15)
RuntimeApiMethodParamMetadataV15 = Struct(name=Text, type=SiLookupTypeId)
RuntimeApiMethodMetadataV15 = Struct(
    name=Text, inputs=Vec(RuntimeApiMethodParamMetadataV15), output=SiLookupTypeId, docs=Vec(Text)
).impl(GenericRuntimeApiMethodMetadata)

RuntimeApiMetadataV15 = Struct(
    name=Text, methods=Vec(RuntimeApiMethodMetadataV15), docs=Vec(Text)
).impl(GenericRuntimeApiMetadata)

MetadataV15 = Struct(
    types=PortableRegistry,
    pallets=Vec(PalletMetadataV15),
    extrinsic=ExtrinsicMetadataV15,
    runtime_type=SiLookupTypeId,
    apis=Vec(RuntimeApiMetadataV15),
    outer_enums=OuterEnums15,
    custom=Vec(CustomMetadata15)
)

MetadataAll = Enum(
    V0=TypeNotSupported("MetadataV0"),
    V1=TypeNotSupported("MetadataV1"),
    V2=TypeNotSupported("MetadataV2"),
    V3=TypeNotSupported("MetadataV3"),
    V4=TypeNotSupported("MetadataV4"),
    V5=TypeNotSupported("MetadataV5"),
    V6=TypeNotSupported("MetadataV6"),
    V7=TypeNotSupported("MetadataV7"),
    V8=TypeNotSupported("MetadataV8"),
    V9=TypeNotSupported("MetadataV9"),
    V10=TypeNotSupported("MetadataV10"),
    V11=TypeNotSupported("MetadataV11"),
    V12=TypeNotSupported("MetadataV12"),
    V13=TypeNotSupported("MetadataV13"),
    V14=MetadataV14,
    V15=MetadataV15
).impl(MetadataAllType)

MetadataVersioned = Tuple(Array(U8, 4), MetadataAll).impl(GenericMetadataVersioned)
