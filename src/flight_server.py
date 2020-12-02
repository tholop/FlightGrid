import argparse
import ast
import threading
import time

import numpy as np
import pyarrow
import pyarrow.flight


from syft.exceptions import EmptyCryptoPrimitiveStoreError
from syft.exceptions import GetNotPermittedError
from syft.exceptions import ResponseSignatureError

import logging


class FlightServer(pyarrow.flight.FlightServerBase):
    def __init__(
        self,
        host="localhost",
        location=None,
        tls_certificates=None,
        verify_client=False,
        root_certificates=None,
        auth_handler=None,
        local_worker=None,
    ):
        super(FlightServer, self).__init__(
            location, auth_handler, tls_certificates, verify_client, root_certificates
        )
        self.flights = {}
        self.host = host
        self.tls_certificates = tls_certificates
        self.local_worker = local_worker

    def do_put(self, context, descriptor, reader, writer):

        # Read the first (and only) record, discard the metadata
        record_batch = reader.read_chunk().data

        # The first two buffers hold some metadata about the binary array
        message_buffer = record_batch[0].buffers()[2]

        # The local worker is a virtual worker, will deserialize with Arrow
        response = self.forward_binary_message_arrow(message_buffer)

        # Write the response in the metadata field (short response in bytes)
        writer.write(r)

    def forward_binary_message_arrow(self, message) -> bin:
        """Forward binary syft messages to user's workers.

        Args:
            message (bin) : pyarrow?
        Returns:
            response (bin) : PySyft binary response.
        """
        try:
            # The decoded response is in bytes
            decoded_response = self.local_worker._recv_msg_arrow(message)

        except (
            EmptyCryptoPrimitiveStoreError,
            GetNotPermittedError,
            ResponseSignatureError,
        ) as e:
            # Register this request into tensor owner account.
            # if hasattr(current_user, "save_tensor_request"):
            #     message = sy.serde.deserialize(message, worker=current_user.worker)
            #     current_user.save_request(message._contents)

            # TODO: no need for pyarrow serde.
            decoded_response = sy.serde.serialize(e)
        return decoded_response


if __name__ == "__main__":
    scheme = "grpc+tcp"
    host = "0.0.0.0"
    port = "7605"
    location = "{}://{}:{}".format(scheme, host, port)
    flight = FlightServer(host, location)
    logging.info("Starting flight")
    flight.serve()