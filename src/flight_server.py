import argparse
import ast
import threading
import time

import numpy as np
import pyarrow
import pyarrow.flight

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

    def do_put(self, context, descriptor, reader, writer):
        key = FlightServer.descriptor_to_key(descriptor)
        t = time.time()
        print(f"Got a new key: {key}")

        table = reader.read_all()
        # n = np.asarray(table.to_pandas())
        # self.flights[key] = reader.read_all()
        dl_time = time.time() - t
        print("Read all and converted to numpy:")
        n = np.asarray(table.to_pandas())
        # print(self.flights[key])
        print(n.shape)
        print(f"Time: {dl_time}")
        print(f"Bandwidth (Gb/s): {(n.nbytes / 1_000_000_000) / dl_time }")

        local_worker.swallow_numpy_array(n)

        response = self.forward_binary_message_arrow(message)

        # TODO: send the response somehow?

    def forward_binary_message_arrow(self, message: bin) -> bin:
        """Forward binary syft messages to user's workers.

        Args:
            message (bin) : PySyft binary message.
        Returns:
            response (bin) : PySyft binary response.
        """
        try:
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