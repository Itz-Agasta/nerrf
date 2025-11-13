"""
NERRF AI Module - M2 AI Spike
=============================

PyTorch-based AI components for anomaly detection and recovery planning.

Components:
    - datasets/: PyTorch Geometric datasets for temporal graphs
    - models/: GraphSAGE-T and LSTM neural networks  
    - utils/: RocksDB storage and data processing utilities

Usage:
    from ai.datasets import NERRFDataset, create_dataloader
    from ai.utils import RocksDBEventStore
"""

__version__ = "0.2.0-m2"
__author__ = "NERRF Team"