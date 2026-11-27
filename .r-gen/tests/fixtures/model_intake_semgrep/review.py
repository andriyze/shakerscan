import importlib
import torch


def load(path):
    importlib.import_module("reviewed_local_module")
    return torch.load(path)
