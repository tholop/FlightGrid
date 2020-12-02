# Standard python
import json

from syft.codes import RESPONSE_MSG
from syft.grid.clients.data_centric_fl_client import DataCentricFLClient

# from main import hook, local_worker, sy
from worker import sy, hook, local_worker
from codes import MSG_FIELD


def get_node_infos(message: dict) -> dict:
    """Returns node id.

    Returns:
        response (dict) : Response message containing node id.
    """
    return {
        RESPONSE_MSG.NODE_ID: local_worker.id,
        MSG_FIELD.SYFT_VERSION: sy.version.__version__,
    }


# def authentication(message: dict) -> dict:
#     """Receive user credentials and performs user authentication.

#     Args:
#         message (dict) : Dict data structure containing user credentials.
#     Returns:
#         response (dict) : Authentication response message.
#     """
#     user = get_session().authenticate(message)
#     # If it was authenticated
#     if user:
#         login_user(user)
#         return {RESPONSE_MSG.SUCCESS: "True", RESPONSE_MSG.NODE_ID: user.worker.id}
#     else:
#         return {RESPONSE_MSG.ERROR: "Invalid username/password!"}


def connect_grid_nodes(message: dict) -> dict:
    """Connect remote grid nodes between each other.

    Args:
        message (dict) :  Dict data structure containing node_id, node address and user credentials(optional).
    Returns:
        response (dict) : response message.
    """
    if message["id"] not in local_worker._known_workers:
        worker = DataCentricFLClient(hook, address=message["address"], id=message["id"])
    return {"status": "Succesfully connected."}
