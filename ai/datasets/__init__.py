"""NERRF Datasets Module"""

# Import core functionality (no PyTorch dependencies)
from .nerrf_dataset_core import NERRFEvent, TemporalGraphBuilder, NERRFDatasetCore

# Try to import PyTorch version if available
try:
    from .nerrf_dataset import NERRFDataset, create_dataloader
    HAS_PYTORCH = True
except ImportError:
    # PyTorch not available, use core version
    NERRFDataset = NERRFDatasetCore
    create_dataloader = None
    HAS_PYTORCH = False

__all__ = ["NERRFDataset", "NERRFEvent", "TemporalGraphBuilder", "NERRFDatasetCore"]
if HAS_PYTORCH:
    __all__.append("create_dataloader")