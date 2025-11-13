"""
NERRF Dataset Loader - Lightweight Core
=======================================

Core event processing logic without heavy ML dependencies.
This module can be used for testing and development without requiring PyTorch.

Features:
    - Event parsing from JSONL/RocksDB
    - Temporal graph construction 
    - Basic feature extraction
    - Data preparation for ML pipelines

For full PyTorch Geometric integration, install requirements.txt first.
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union
from datetime import datetime, timedelta
import pandas as pd
import networkx as nx

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
    
    def extract_features(self, G: nx.DiGraph) -> Tuple[List[List[float]], List[List[float]]]:
        """
        Extract node and edge features as lists (for later conversion to tensors).
        
        Returns:
            node_features: List of node feature vectors
            edge_features: List of edge feature vectors
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
        
        return node_features, edge_features


class NERRFDatasetCore:
    """
    Core dataset functionality without PyTorch dependencies.
    
    Provides event loading, windowing, and graph construction
    that can be later converted to PyTorch Geometric format.
    """
    
    def __init__(self, data_path: Union[str, Path], 
                 window_size: timedelta = timedelta(minutes=5),
                 stride: timedelta = timedelta(minutes=1),
                 data_format: str = "jsonl"):
        """
        Initialize dataset.
        
        Args:
            data_path: Path to data source (JSONL file)
            window_size: Time window for graph construction
            stride: Sliding window stride
            data_format: "jsonl" only for now
        """
        self.data_path = Path(data_path)
        self.window_size = window_size
        self.stride = stride
        self.data_format = data_format
        
        self.graph_builder = TemporalGraphBuilder(window_size)
        self.events = self._load_events()
        self.windows = self._create_windows()
        
        logger.info(f"Loaded {len(self.events)} events, created {len(self.windows)} windows")
    
    def _load_events(self) -> List[NERRFEvent]:
        """Load events from JSONL file."""
        events = []
        
        if not self.data_path.exists():
            logger.warning(f"Data file not found: {self.data_path}")
            return events
        
        with open(self.data_path, 'r') as f:
            for line in f:
                try:
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
                except Exception as e:
                    logger.warning(f"Failed to parse line: {e}")
                    continue
        
        return events
    
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
    
    def get_window_data(self, idx: int) -> Dict:
        """
        Get processed data for a window (without PyTorch tensors).
        
        Returns:
            Dictionary with graph data, features, and label
        """
        if idx >= len(self.windows):
            raise IndexError(f"Index {idx} out of range")
        
        window_start, window_end = self.windows[idx]
        window_events = self._events_in_window(window_start, window_end)
        
        if not window_events:
            # Return empty data
            return {
                "node_features": [[1.0, 0.0, 0.0, 0.0, 0.0]],  # Single dummy node
                "edge_features": [],
                "edge_index": [],
                "label": 0.0,  # Benign
                "num_nodes": 1,
                "num_edges": 0,
                "window_start": window_start,
                "window_end": window_end,
                "events": []
            }
        
        # Build temporal graph
        G = self.graph_builder.build_graph(window_events)
        
        # Extract features
        node_features, edge_features = self.graph_builder.extract_features(G)
        
        # Create edge index (list of [source, target] pairs)
        edge_index = []
        node_list = list(G.nodes())
        for u, v in G.edges():
            source_idx = node_list.index(u)
            target_idx = node_list.index(v)
            edge_index.append([source_idx, target_idx])
        
        # Graph-level label (malicious if any event is malicious)
        is_malicious = any(event.is_malicious for event in window_events)
        
        return {
            "node_features": node_features,
            "edge_features": edge_features,  
            "edge_index": edge_index,
            "label": float(is_malicious),
            "num_nodes": len(G.nodes()),
            "num_edges": len(G.edges()),
            "window_start": window_start,
            "window_end": window_end,
            "events": window_events
        }
    
    def get_statistics(self) -> Dict:
        """Get dataset statistics."""
        if not self.events:
            return {}
        
        malicious_events = sum(1 for event in self.events if event.is_malicious)
        phases = {}
        file_types = {}
        
        for event in self.events:
            phases[event.phase] = phases.get(event.phase, 0) + 1
            file_types[event.file_extension] = file_types.get(event.file_extension, 0) + 1
        
        return {
            "total_events": len(self.events),
            "malicious_events": malicious_events,
            "benign_events": len(self.events) - malicious_events,
            "total_windows": len(self.windows),
            "phases": phases,
            "file_types": file_types,
            "time_span": {
                "start": min(event.timestamp for event in self.events),
                "end": max(event.timestamp for event in self.events)
            }
        }


if __name__ == "__main__":
    # Example usage with benchmark data
    data_path = "/workspaces/neerf/benchmarks/m1/results/m1_trace.jsonl"
    
    if Path(data_path).exists():
        # Create dataset
        dataset = NERRFDatasetCore(data_path, 
                                 window_size=timedelta(minutes=2),
                                 stride=timedelta(minutes=1))
        
        print(f"Dataset size: {len(dataset)}")
        
        # Get statistics
        stats = dataset.get_statistics()
        print(f"Dataset statistics: {stats}")
        
        # Get first sample
        if len(dataset) > 0:
            sample = dataset.get_window_data(0)
            print(f"Sample: {sample['num_nodes']} nodes, {sample['num_edges']} edges")
            print(f"Label: {'malicious' if sample['label'] > 0.5 else 'benign'}")
            print(f"Events in window: {len(sample['events'])}")
    else:
        print(f"Benchmark data not found at {data_path}")
        print("Run M1 benchmarks first to generate training data")