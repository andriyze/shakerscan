import torch
from safetensors.torch import load_file


def load(path):
    if str(path).endswith(".safetensors"):
        return load_file(path)
    return torch.load(path, weights_only=True, map_location="cpu")
