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
from typing import TYPE_CHECKING

import math
from datetime import datetime, timedelta

__all__ = ['Extension', 'SearchExtension', 'SubstrateNodeSearchExtension']

if TYPE_CHECKING:
    from .base import SubstrateInterface


class Extension:
    """
    Base class of all extensions
    """
    def __init__(self):
        self.substrate = None

    def init(self, substrate: 'SubstrateInterface'):
        """
        Initialization process of the extension. This function is being called by the ExtensionRegistry.

        Parameters
        ----------
        substrate: SubstrateInterface

        Returns
        -------

        """
        self.substrate: 'SubstrateInterface' = substrate

    def close(self):
        """
        Cleanup process of the extension. This function is being called by the ExtensionRegistry.

        Returns
        -------

        """
        pass

    def debug_message(self, message: str):
        """
        Submits a debug message in the logger

        Parameters
        ----------
        message: str

        Returns
        -------

        """
        self.substrate.debug_message(f'Extension {self.__class__.__name__}: {message}')


class SearchExtension(Extension):
    """
    Type of `Extension` that implements functionality to improve and enhance search capability
    """

    def filter_events(self, **kwargs) -> list:
        """
        Filters events to match provided search criteria e.g. block range, pallet name, accountID in attributes

        Parameters
        ----------
        kwargs

        Returns
        -------
        list
        """
        raise NotImplementedError()

    def filter_extrinsics(self, **kwargs) -> list:
        """
        Filters extrinsics to match provided search criteria e.g. block range, pallet name, signed by accountID

        Parameters
        ----------
        kwargs

        Returns
        -------

        """
        raise NotImplementedError()

    def search_block_number(self, block_datetime: datetime, block_time: int = 6, **kwargs) -> int:
        """
        Search corresponding block number for provided `block_datetime`. the prediction tolerance is provided with
        `block_time`

        Parameters
        ----------
        block_datetime: datetime
        block_time: int
        kwargs

        Returns
        -------
        int
        """
        raise NotImplementedError()

    def get_block_timestamp(self, block_number: int) -> int:
        """
        Return a UNIX timestamp for given `block_number`.

        Parameters
        ----------
        block_number: int The block_number to retrieve the timestamp for

        Returns
        -------
        int
        """
        raise NotImplementedError()


class SubstrateNodeSearchExtension(SearchExtension):
    """
    Implementation of `SearchExtension` using only Substrate RPC methods. Could be significant inefficient.
    """

    def filter_extrinsics(self, block_start: int = None, block_end: int = None, ss58_address: str = None,
                          pallet_name: str = None, call_name: str = None) -> list:

        if block_end is None:
            block_end = self.substrate.get_block_number(None)

        if block_start is None:
            block_start = block_end

        if block_start < 0:
            block_start += block_end

        result = []

        for block_number in range(block_start, block_end + 1):
            block_hash = self.substrate.get_block_hash(block_number)

            for extrinsic in self.substrate.get_extrinsics(block_hash=block_hash):
                if pallet_name is not None and pallet_name != extrinsic.value['call']['call_module']:
                    continue

                if call_name is not None and call_name != extrinsic.value['call']['call_function']:
                    continue

                result.append(extrinsic)

        return result

    def __init__(self, max_block_range: int = 100):
        super().__init__()

        self.max_block_range: int = max_block_range

    def filter_events(self, block_start: int = None, block_end: int = None, pallet_name: str = None,
                      event_name: str = None, account_id: str = None) -> list:

        if block_end is None:
            block_end = self.substrate.get_block_number(None)

        if block_start is None:
            block_start = block_end

        if block_start < 0:
            block_start += block_end

        # Requirements check
        if block_end - block_start > self.max_block_range:
            raise ValueError(f"max_block_range ({self.max_block_range}) exceeded")

        result = []

        self.debug_message(f"Retrieving events from #{block_start} to #{block_end}")

        for block_number in range(block_start, block_end + 1):
            block_hash = self.substrate.get_block_hash(block_number)
            for event in self.substrate.get_events(block_hash=block_hash):
                if pallet_name is not None and pallet_name != event.value['event']['module_id']:
                    continue

                if event_name is not None and event_name != event.value['event']['event_id']:
                    continue

                # if account_id is not None:
                #     found = False
                #     for param in event.params:
                #         if param['type'] == 'AccountId' and param['value'] == account_id:
                #             found = True
                #             break
                #     if not found:
                #         continue

                result.append(event)

        return result

    def get_block_timestamp(self, block_number: int) -> int:
        extrinsics = self.filter_extrinsics(
            block_start=block_number, block_end=block_number, pallet_name="Timestamp",
            call_name="set"
        )
        return extrinsics[0].value['call']['call_args'][0]['value'] / 1000

    def search_block_number(self, block_datetime: datetime, block_time: int = 6, **kwargs) -> int:
        """
        Search corresponding block number for provided `block_datetime`. the prediction tolerance is provided with
        `block_time`

        Parameters
        ----------
        block_datetime: datetime
        block_time: int
        kwargs

        Returns
        -------
        int
        """
        accuracy = timedelta(seconds=block_time)

        target_block_timestamp = block_datetime.timestamp()

        # Retrieve Timestamp extrinsic for chain tip
        predicted_block_number = self.substrate.get_block_number(None)
        current_timestamp = self.get_block_timestamp(predicted_block_number)
        current_delta = current_timestamp - target_block_timestamp

        self.debug_message(f"Delta {current_delta} sec with chain tip #{predicted_block_number}")

        if current_delta < 0:
            raise ValueError("Requested block_datetime is higher than current chain tip")

        while accuracy < timedelta(seconds=math.fabs(current_delta)):

            predicted_block_number = math.ceil(predicted_block_number - current_delta / block_time)

            if predicted_block_number < 0:
                raise ValueError(f"Requested datetime points before genesis of chain (#{predicted_block_number})")

            current_timestamp = self.get_block_timestamp(predicted_block_number)

            # Predict target block number
            current_delta = current_timestamp - target_block_timestamp

            self.debug_message(f"Current delta {current_delta} sec; predicted #{predicted_block_number}")

        self.debug_message(f"Accepted prediction #{predicted_block_number}")

        return predicted_block_number
