# Copyright 2021 Vincent Texier <vit@free.fr>
#
# This software is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
import logging
import time
from queue import Queue
from threading import Thread

from substrateinterface import SubstrateInterface


class ThreadSafe(Thread):

    queue: Queue = Queue()

    def __init__(self, *args, **kwargs):
        """
        Init a SubstrateInterface client adapter instance as a thread

        :param args: Positional arguments
        :param kwargs: Keywords arguments
        """
        super().__init__(*args, **kwargs)

    def run(self):
        """
        Started asynchronously with Thread.start()

        :return:
        """
        while True:
            # print("loop...")
            call, method, args, result_handler, result = self.queue.get()
            result_ = dict()
            # print(call, method, args, result_handler, result)
            if call == "--close--":
                logging.debug("Close queue thread on substrate_interface")
                break

            try:
                # logging.debug(f"threadsafe call to rpc method {method}")
                result_ = call(method, args, result_handler)
            except Exception as exception:
                logging.error(method)
                logging.error(args)
                # logging.exception(exception)
                result.put(exception)
            # print(call.__name__, " put result ", result_)
            result.put(result_)
            # print("reloop...")

        logging.debug("SubstrateInterface connection closed and thread terminated.")

    def close(self):
        """
        Close connection

        :return:
        """
        # Closing the connection
        self.queue.put(("--close--", None, None, None, None))


class ThreadSafeSubstrateInterface(SubstrateInterface):
    """
    Override substrate_interface client class with a queue to be thread safe

    """

    def __init__(self, *args, **kwargs):
        """
        Init a SubstrateInterface client adapter instance as a thread

        :param args: Positional arguments
        :param kwargs: Keywords arguments
        """
        # create and start thread before calling parent init (which makes a rpc_request!)
        self.thread = ThreadSafe()
        self.thread.start()

        super().__init__(*args, **kwargs)

    def rpc_request(self, method, params, result_handler=None) -> dict:
        """
        Override rpc_request method to use threadsafe queue

        :param method: Name of the RPC method
        :param params: Params of the RPC method
        :param result_handler: Optional variable to receive results, default to None
        :return:
        """
        result: Queue = Queue()
        self.thread.queue.put(
            (super().rpc_request, method, params, result_handler, result)
        )
        # print(self.thread.queue.get())
        # print('done calling %s' % method)
        return_ = result.get()
        if isinstance(return_, Exception):
            raise return_
        return return_

    def close(self):
        logging.debug("Close RPC connection thread")
        self.thread.close()


if __name__ == '__main__':
    # start Substrate instance as a thread...
    substrate = ThreadSafeSubstrateInterface(
        url="ws://127.0.0.1:9944"
    )
    while True:
        substrate.get_block()
        number = substrate.get_block_number(substrate.block_hash)
        print(number,  substrate.block_hash, substrate.version, substrate.runtime_version)
        time.sleep(6)
