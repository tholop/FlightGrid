import argparse
import ast
import threading
import time
import logging
import json

import numpy as np
import pyarrow
import pyarrow.flight

from syft.codes import REQUEST_MSG
from codes import MSG_FIELD

from syft.exceptions import EmptyCryptoPrimitiveStoreError
from syft.exceptions import GetNotPermittedError
from syft.exceptions import ResponseSignatureError

from events import get_node_infos, connect_grid_nodes

from worker import sy


routes = {
    # CONTROL_EVENTS.SOCKET_PING: socket_ping,
    # MODEL_CENTRIC_FL_EVENTS.HOST_FL_TRAINING: host_federated_training,
    # MODEL_CENTRIC_FL_EVENTS.AUTHENTICATE: authenticate,
    # MODEL_CENTRIC_FL_EVENTS.CYCLE_REQUEST: cycle_request,
    # MODEL_CENTRIC_FL_EVENTS.REPORT: report,
    # USER_EVENTS.SIGNUP_USER: signup_user_socket,
    # USER_EVENTS.LOGIN_USER: login_user_socket,
    # USER_EVENTS.GET_ALL_USERS: get_all_users_socket,
    # USER_EVENTS.GET_SPECIFIC_USER: get_specific_user_socket,
    # USER_EVENTS.SEARCH_USERS: search_users_socket,
    # USER_EVENTS.PUT_EMAIL: change_user_email_socket,
    # USER_EVENTS.PUT_PASSWORD: change_user_password_socket,
    # USER_EVENTS.PUT_ROLE: change_user_role_socket,
    # USER_EVENTS.PUT_GROUPS: change_user_groups_socket,
    # USER_EVENTS.DELETE_USER: delete_user_socket,
    # ROLE_EVENTS.CREATE_ROLE: create_role_socket,
    # ROLE_EVENTS.GET_ROLE: get_role_socket,
    # ROLE_EVENTS.GET_ALL_ROLES: get_all_roles_socket,
    # ROLE_EVENTS.PUT_ROLE: put_role_socket,
    # ROLE_EVENTS.DELETE_ROLE: delete_role_socket,
    # GROUP_EVENTS.CREATE_GROUP: create_group_socket,
    # GROUP_EVENTS.GET_GROUP: get_group_socket,
    # GROUP_EVENTS.GET_ALL_GROUPS: get_all_groups_socket,
    # GROUP_EVENTS.PUT_GROUP: put_group_socket,
    # GROUP_EVENTS.DELETE_GROUP: delete_group_socket,
    REQUEST_MSG.GET_ID: get_node_infos,
    REQUEST_MSG.CONNECT_NODE: connect_grid_nodes,
    # REQUEST_MSG.HOST_MODEL: host_model,
    # REQUEST_MSG.RUN_INFERENCE: run_inference,
    # REQUEST_MSG.DELETE_MODEL: delete_model,
    # REQUEST_MSG.LIST_MODELS: get_models,
    # REQUEST_MSG.AUTHENTICATE: authentication,
}


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
        self.location = location
        self.tls_certificates = tls_certificates
        self.local_worker = local_worker

    @classmethod
    def descriptor_to_key(self, descriptor):
        return (
            descriptor.descriptor_type.value,
            descriptor.command,
            tuple(descriptor.path or tuple()),
        )

    def do_put(self, context, descriptor, reader, writer):

        # Check the type of the message
        key = FlightServer.descriptor_to_key(descriptor)
        logging.info(f"Server {self.location[-5:]} received stuff: {key}")

        # TODO: nicer encoding for the commands
        if key[1] in [b"fss_eq", b"fss_comp"]:
            table = reader.read_all()
            n = np.asarray(table.to_pandas())
            op = "fss_eq" if key[1] == b"fss_eq" else "fss_comp"
            logging.info(
                f"Feeding primitives for {op} with shape {n.shape} and type {n.dtype}: \n {n}"
            )
            logging.info(f"Creating a stupid message")

            # self.local_worker.feed_crypto_primitive_store({op: n})
            worker_message = self.local_worker.create_worker_command_message(
                "feed_crypto_primitive_store", None, {op: n}
            )
            # TODO: wrong worker??
            bin_message = sy.serde.serialize(worker_message, worker=self.local_worker)
            response = self.forward_binary_message(bin_message)
            # logging.info(f"Asking gently: {worker_message}")
            # logging.info(f"This is being handled by {self.local_worker}")
            # for handler in self.local_worker.message_handlers:
            #     if handler.supports(worker_message):
            #         logging.info(f"Handling {type(worker_message)} with {handler}")
            #         response = handler.handle(worker_message)
            #         logging.info("Finished handling.")
            #         break
            # self.local_worker._recv_msg(worker_message)
            logging.info(f"Done. \n response?{response}")
        else:
            # Read the first (and only) record, discard the metadata
            record_batch = reader.read_chunk().data

            # The first two buffers hold some metadata about the binary array
            message_buffer = record_batch[0].buffers()[2]

            if key[1] == b"json":
                # logging.info("Got json.")
                request_id = None
                try:
                    message_dict = json.loads(
                        message_buffer.to_pybytes().decode("utf-8")
                    )
                    # logging.info(f"Deserialized message: {message_dict}")
                    request_id = message_dict.get(MSG_FIELD.REQUEST_ID)
                    response = routes[message_dict[REQUEST_MSG.TYPE_FIELD]](
                        message_dict
                    )
                except Exception as e:
                    response = {"error": str(e)}
                if request_id:
                    response[MSG_FIELD.REQUEST_ID] = request_id

                # logging.info(f"Response: {response}")
                bin_response = json.dumps(response).encode("utf-8")

            else:
                # logging.info(f"Got binary message: {message_buffer}")
                # The local worker is a virtual worker, will deserialize with Arrow
                # and send a response in bytes
                # bin_response = self.forward_binary_message_arrow(message_buffer)

                bin_message = message_buffer.to_pybytes()
                logging.info(f"Received {len(bin_message)} bytes.")
                bin_response = self.forward_binary_message(bin_message)
                logging.info(f"Writing bin response: {len(bin_response)}")
            # Write the response in the metadata field (short response in bytes)
            writer.write(bin_response)

    def forward_binary_message(self, message: bin) -> bin:
        """Forward binary syft messages to user's workers.

        Args:
            message (bin) : a very normal pybytes
        Returns:
            response (bin) : PySyft binary response.
        """
        # logging.info(f"Forwarding arrow")
        try:
            # The decoded response is in bytes
            logging.info(f"{self.local_worker} is receiving a message")
            decoded_response = self.local_worker._recv_msg(message)
            # logging.info(f"Got a response: {decoded_response}")
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
            # logging.info(f"Got an error: {e}")

            decoded_response = sy.serde.serialize(e)
        return decoded_response

    def forward_binary_message_arrow(self, message) -> bin:
        """Forward binary syft messages to user's workers.

        Args:
            message (bin) : pyarrow?
        Returns:
            response (bin) : PySyft binary response.
        """
        # logging.info(f"Forwarding arrow")
        try:
            # The decoded response is in bytes
            decoded_response = self.local_worker._recv_msg_arrow(message)
            # logging.info(f"Got a response: {decoded_response}")
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
            # logging.info(f"Got an error: {e}")

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