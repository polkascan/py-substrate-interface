# Python Substrate Interface
#
# Copyright 2018-2019 openAware BV (NL).
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

import binascii
import xxhash
import json
import requests

from scalecodec import ScaleBytes
from scalecodec.base import ScaleDecoder
from scalecodec.block import ExtrinsicsDecoder, EventsDecoder
from scalecodec.metadata import MetadataDecoder
from .exceptions import SubstrateRequestException
from .constants import *


class SubstrateInterface:

    def __init__(self, url):
        self.request_id = 1
        self.url = url
        self.default_headers = {
            'content-type': "application/json",
            'cache-control': "no-cache"
        }

    def __rpc_request(self, method, params):

        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": self.request_id
        }

        response = requests.request("POST", self.url, data=json.dumps(payload), headers=self.default_headers)

        self.request_id += 1

        if response.status_code != 200:
            raise SubstrateRequestException("RPC request failed with HTTP status code {}".format(response.status_code))

        json_body = response.json()

        if json_body.get('error'):
            raise SubstrateRequestException("RPC request failed with error code {} and message \"{}\"".format(
                json_body['error']['code'],
                json_body['error']['message']
            ))

        return json_body

    def get_system_name(self):
        response = self.__rpc_request("system_name", [])
        return response.get('result')

    def get_chain_head(self):
        response = self.__rpc_request("chain_getHead", [])
        return response.get('result')

    def get_chain_finalised_head(self):
        response = self.__rpc_request("chain_getFinalisedHead", [])
        return response.get('result')

    def get_chain_block(self, block_hash=None, block_id=None, metadata_decoder=None):

        if block_id:
            block_hash = self.get_block_hash(block_hash)

        response = self.__rpc_request("chain_getBlock", [block_hash]).get('result')

        # Decode extrinsics
        if metadata_decoder:
            for idx, extrinsic_data in enumerate(response['block']['extrinsics']):
                extrinsic_decoder = ExtrinsicsDecoder(
                    data=ScaleBytes(extrinsic_data),
                    metadata=metadata_decoder
                )
                extrinsic_decoder.decode()
                response['block']['extrinsics'][idx] = extrinsic_decoder

        return response

    def get_block_hash(self, block_id):
        return self.__rpc_request("chain_getBlockHash", [block_id]).get('result')

    def get_block_header(self, block_hash):
        response = self.__rpc_request("chain_getHeader", [block_hash])
        return response.get('result')

    def get_block_metadata(self, block_hash, decode=True):
        response = self.__rpc_request("state_getMetadata", [block_hash])

        if response.get('result'):

            if decode:
                metadata_decoder = MetadataDecoder(ScaleBytes(response.get('result')))
                metadata_decoder.decode()
                
                return metadata_decoder
        
            return response
        else:
            raise SubstrateRequestException("Error occurred during retrieval of metadata")

    def get_storage(self, block_hash, module, function, params=None, return_scale_type=None):
        """
        Retrieves the storage for given given module, function and optional paramaters at given block
        :param return_scale_type: Scale type string to interprete result
        :param block_hash:
        :param module:
        :param function:
        :param params:
        :return:
        """
        storage_hash = self.generate_storage_hash(module, function, params)
        response = self.__rpc_request("state_getStorageAt", [storage_hash, block_hash])

        if 'result' in response:

            if return_scale_type and response.get('result'):
                obj = ScaleDecoder.get_decoder_class(return_scale_type, ScaleBytes(response.get('result')))
                return obj.decode()
            else:
                return response.get('result')
        else:
            raise SubstrateRequestException("Error occurred during retrieval of events")

    def get_block_events(self, block_hash, metadata_decoder=None):
        response = self.__rpc_request("state_getStorageAt", [STORAGE_HASH_SYSTEM_EVENTS, block_hash])

        if response.get('result'):

            if metadata_decoder:

                # Process events
                events_decoder = EventsDecoder(
                    data=ScaleBytes(response.get('result')),
                    metadata=metadata_decoder
                )
                events_decoder.decode()

                return events_decoder

            else:
                return response
        else:
            raise SubstrateRequestException("Error occurred during retrieval of events")

    def get_block_runtime_version(self, block_hash):
        response = self.__rpc_request("chain_getRuntimeVersion", [block_hash])
        return response.get('result')

    @staticmethod
    def generate_storage_hash(storage_module, storage_function, params=None):
        """
        Generate a storage key for given module/function
        :param storage_module:
        :param storage_function:
        :param params:
        :return:
        """
        storage_function = storage_module.encode() + b" " + storage_function.encode()
        if params:
            storage_function += binascii.unhexlify(params)

        storage_key1 = bytearray(xxhash.xxh64(storage_function, seed=0).digest())
        storage_key1.reverse()

        storage_key2 = bytearray(xxhash.xxh64(storage_function, seed=1).digest())
        storage_key2.reverse()

        return "0x{}{}".format(storage_key1.hex(), storage_key2.hex())
