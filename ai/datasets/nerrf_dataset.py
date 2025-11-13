"""
NERRF Dataset Loader - M2 AI Spike
==================================

PyTorch Geometric dataset loader that converts filesystem events from RocksDB/JSONL
into temporal graphs for anomaly detection models.

Architecture:
    Events → Temporal Graph → PyTorch Geometric Data → GraphSAGE-T + LSTM

Features:
    - RocksDB backend for persistent storage
    - JSONL fallback for benchmark data
    - Temporal graph construction with sliding windows
    - Node features: file paths, processes, syscalls
    - Edge features: temporal relationships, causality
    - Label support for supervised learning

Author: NERRF Team
License: AGPL v3
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union
from datetime import datetime, timedelta
import pandas as pd
import numpy as np
import networkx as nx

import torch
from torch_geometric.data import Data, Dataset
from torch_geometric.utils import from_networkx

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class NERRFEvent:
    """
    Represents a single filesystem event from NERRF tracker.
    
    Attributes:
        timestamp: Event occurrence time
        event_type: Type of operation (file_created, write, etc.)
        path: File path involved
        pid: Process ID
        phase: Attack phase (reconnaissance, preparation, execution, etc.)
        size: File size in bytes
        syscall: System call name (openat, write, rename)
    """
    
    def __init__(self, timestamp: str, event_type: str, path: str, 
                 pid: int, phase: str = "benign", size: int = 0, 
                 syscall: str = "unknown", **kwargs):
        self.timestamp = pd.to_datetime(timestamp)
        self.event_type = event_type
        self.path = Path(path)
        self.pid = pid
        self.phase = phase
        self.size = size
        self.syscall = syscall
        self.metadata = kwargs
    
    def __repr__(self):
        return f"NERRFEvent({self.timestamp}, {self.event_type}, {self.path})"
    
    @property
    def is_malicious(self) -> bool:
        """Check if event is part of an attack phase."""
        malicious_phases = ["reconnaissance", "preparation", "execution", "encryption", "exfiltration"]
        return self.phase in malicious_phases
    
    @property
    def file_extension(self) -> str:
        """Extract file extension for analysis."""
        return self.path.suffix.lower()
    
    @property
    def directory(self) -> str:
        """Get parent directory path."""
        return str(self.path.parent)


class TemporalGraphBuilder:
    """
    Converts sequences of filesystem events into temporal graphs.
    
    Graph Structure:
        - Nodes: Files, processes, directories
        - Edges: Temporal relationships (process → file, file → file)
        - Features: Path embeddings, time deltas, operation types
    """
    
    def __init__(self, window_size: timedelta = timedelta(minutes=5)):
        self.window_size = window_size
        self.node_vocab = {"<UNK>": 0, "<PAD>": 1}
        self.edge_vocab = {"temporal": 0, "causal": 1, "spatial": 2}
        
    def build_graph(self, events: List[NERRFEvent]) -> nx.DiGraph:
        """
        Build temporal graph from event sequence.
        
        Args:
            events: List of filesystem events within time window
            
        Returns:
            NetworkX directed graph with node/edge features
        """
        G = nx.DiGraph()
        
        # Sort events by timestamp
        events = sorted(events, key=lambda e: e.timestamp)
        
        for i, event in enumerate(events):
            # Add process node
            process_id = f"pid_{event.pid}"
            if not G.has_node(process_id):
                G.add_node(process_id, 
                          node_type="process",
                          pid=event.pid,
                          first_seen=event.timestamp)
            
            # Add file node
            file_id = str(event.path)
            if not G.has_node(file_id):
                G.add_node(file_id,
                          node_type="file", 
                          path=str(event.path),
                          directory=event.directory,
                          extension=event.file_extension,
                          first_seen=event.timestamp)
            
            # Add process → file edge
            G.add_edge(process_id, file_id,
                      edge_type="operation",
                      operation=event.event_type,
                      syscall=event.syscall,
                      timestamp=event.timestamp,
                      size=event.size,
                      phase=event.phase,
                      is_malicious=event.is_malicious)
            
            # Add temporal edges between consecutive file operations
            if i > 0:
                prev_event = events[i-1]
                prev_file_id = str(prev_event.path)
                
                time_delta = (event.timestamp - prev_event.timestamp).total_seconds()
                
                # Add temporal relationship if events are close in time
                if time_delta < 60:  # Within 1 minute
                    G.add_edge(prev_file_id, file_id,
                              edge_type="temporal",
                              time_delta=time_delta,
                              sequence_order=i)
        
        return G
    
    def extract_features(self, G: nx.DiGraph) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Extract node and edge features for PyTorch Geometric.
        
        Returns:
            node_features: Tensor of shape [num_nodes, node_feature_dim]
            edge_features: Tensor of shape [num_edges, edge_feature_dim]
        """
        # Node features
        node_features = []
        for node_id in G.nodes():
            node_data = G.nodes[node_id]
            
            # Feature vector: [node_type_onehot, path_hash, time_features]
            if node_data["node_type"] == "process":
                node_type = [1.0, 0.0]  # [process, file]
                path_hash = hash(f"pid_{node_data['pid']}") % 1000 / 1000.0
            else:  # file
                node_type = [0.0, 1.0]
                path_hash = hash(node_data["path"]) % 1000 / 1000.0
            
            # Time features (hour of day, day of week)
            timestamp = node_data["first_seen"]
            time_features = [
                timestamp.hour / 24.0,
                timestamp.weekday() / 7.0
            ]
            
            features = node_type + [path_hash] + time_features
            node_features.append(features)
        
        # Edge features
        edge_features = []
        for u, v, edge_data in G.edges(data=True):
            # Feature vector: [edge_type_onehot, time_delta, size, is_malicious]
            edge_type = edge_data.get("edge_type", "operation")
            
            if edge_type == "operation":
                edge_type_vec = [1.0, 0.0, 0.0]  # [operation, temporal, spatial]
            elif edge_type == "temporal":
                edge_type_vec = [0.0, 1.0, 0.0]
            else:
                edge_type_vec = [0.0, 0.0, 1.0]
            
            time_delta = edge_data.get("time_delta", 0.0)
            size = edge_data.get("size", 0)
            is_malicious = float(edge_data.get("is_malicious", False))
            
            features = edge_type_vec + [
                min(time_delta / 3600.0, 1.0),  # Normalize to hours, cap at 1
                min(size / 1e9, 1.0),           # Normalize to GB, cap at 1
                is_malicious
            ]
            edge_features.append(features)
        
        return torch.tensor(node_features, dtype=torch.float), \
               torch.tensor(edge_features, dtype=torch.float)


class NERRFDataset(Dataset):
    """
    PyTorch Geometric dataset for NERRF temporal graphs.
    
    Supports both RocksDB and JSONL data sources with configurable
    time windows and feature extraction.
    """
    
    def __init__(self, data_path: Union[str, Path], 
                 window_size: timedelta = timedelta(minutes=5),
                 stride: timedelta = timedelta(minutes=1),
                 data_format: str = "jsonl"):
        """
        Initialize dataset.
        
        Args:
            data_path: Path to data source (RocksDB dir or JSONL file)
            window_size: Time window for graph construction
            stride: Sliding window stride
            data_format: "jsonl" or "rocksdb"
        """
        super().__init__()
        
        self.data_path = Path(data_path)
        self.window_size = window_size
        self.stride = stride
        self.data_format = data_format
        
        self.graph_builder = TemporalGraphBuilder(window_size)
        self.events = self._load_events()
        self.windows = self._create_windows()
        
        logger.info(f"Loaded {len(self.events)} events, created {len(self.windows)} windows")
    
    def _load_events(self) -> List[NERRFEvent]:
        """Load events from data source."""
        if self.data_format == "jsonl":
            return self._load_jsonl()
        elif self.data_format == "rocksdb":
            return self._load_rocksdb()
        else:
            raise ValueError(f"Unsupported data format: {self.data_format}")
    
    def _load_jsonl(self) -> List[NERRFEvent]:
        """Load events from JSONL file."""
        events = []
        
        with open(self.data_path, 'r') as f:
            for line in f:
                data = json.loads(line.strip())
                
                # Convert JSONL format to NERRFEvent
                event = NERRFEvent(
                    timestamp=data.get("timestamp"),
                    event_type=data.get("event", "unknown"),
                    path=data.get("path", "/unknown"),
                    pid=data.get("pid", 0),
                    phase=data.get("phase", "benign"),
                    size=data.get("size", 0),
                    syscall=data.get("syscall", "unknown")
                )
                events.append(event)
        
        return events
    
    def _load_rocksdb(self) -> List[NERRFEvent]:
        """Load events from RocksDB (placeholder for M1 integration)."""
        # TODO: Implement RocksDB reader when M1 storage is complete
        logger.warning("RocksDB loading not yet implemented, use JSONL format")
        return []
    
    def _create_windows(self) -> List[Tuple[datetime, datetime]]:
        """Create sliding time windows."""
        if not self.events:
            return []
        
        start_time = min(event.timestamp for event in self.events)
        end_time = max(event.timestamp for event in self.events)
        
        windows = []
        current_start = start_time
        
        while current_start + self.window_size <= end_time:
            current_end = current_start + self.window_size
            windows.append((current_start, current_end))
            current_start += self.stride
        
        return windows
    
    def _events_in_window(self, window_start: datetime, window_end: datetime) -> List[NERRFEvent]:
        """Get events within time window."""
        return [event for event in self.events 
                if window_start <= event.timestamp < window_end]
    
    def __len__(self) -> int:
        return len(self.windows)
    
    def __getitem__(self, idx: int) -> Data:
        """
        Get PyTorch Geometric Data object for window.
        
        Returns:
            Data object with:
                - x: Node features [num_nodes, node_feature_dim]
                - edge_index: Edge connectivity [2, num_edges]
                - edge_attr: Edge features [num_edges, edge_feature_dim]
                - y: Graph-level label (malicious/benign)
        """
        window_start, window_end = self.windows[idx]
        window_events = self._events_in_window(window_start, window_end)
        
        if not window_events:
            # Return empty graph
            return Data(x=torch.zeros((1, 5)), 
                       edge_index=torch.zeros((2, 0), dtype=torch.long),
                       edge_attr=torch.zeros((0, 6)),
                       y=torch.tensor([0.0]))  # Benign
        
        # Build temporal graph
        G = self.graph_builder.build_graph(window_events)
        
        # Convert to PyTorch Geometric
        pyg_data = from_networkx(G)
        
        # Extract features
        node_features, edge_features = self.graph_builder.extract_features(G)
        
        # Graph-level label (malicious if any event is malicious)
        is_malicious = any(event.is_malicious for event in window_events)
        
        # Create final Data object
        data = Data(
            x=node_features,
            edge_index=pyg_data.edge_index,
            edge_attr=edge_features,
            y=torch.tensor([float(is_malicious)]),
            num_nodes=len(G.nodes()),
            window_start=window_start,
            window_end=window_end
        )
        
        return data


def create_dataloader(data_path: Union[str, Path], 
                     batch_size: int = 32, 
                     shuffle: bool = True,
                     **dataset_kwargs) -> torch.utils.data.DataLoader:
    """
    Create PyTorch DataLoader for NERRF temporal graphs.
    
    Args:
        data_path: Path to JSONL or RocksDB data
        batch_size: Batch size for training
        shuffle: Whether to shuffle data
        **dataset_kwargs: Additional arguments for NERRFDataset
    
    Returns:
        DataLoader for training/inference
    """
    from torch_geometric.loader import DataLoader
    
    dataset = NERRFDataset(data_path, **dataset_kwargs)
    
    return DataLoader(dataset, 
                     batch_size=batch_size, 
                     shuffle=shuffle,
                     follow_batch=['x', 'edge_index'])


if __name__ == "__main__":
    # Production usage example:
    # dataset = NERRFDataset("/path/to/data.jsonl", window_size=timedelta(minutes=2))
    # dataloader = create_dataloader("/path/to/data.jsonl", batch_size=32)
    pass