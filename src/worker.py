import syft as sy
import torch as th

th.set_num_threads(1)

hook = sy.TorchHook(th)
# local_worker = sy.VirtualWorker(hook, auto_add=False, verbose=True)
local_worker = sy.VirtualWorker(hook, auto_add=False)
hook.local_worker.is_client_worker = False
