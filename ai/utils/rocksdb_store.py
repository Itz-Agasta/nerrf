"""
RocksDB Integration for NERRF M1/M2
==================================

Provides efficient storage and retrieval of eBPF events for AI training.
Supports 30-second delta compaction as specified in M1 requirements.

Features:
    - High-performance event storage (target: ≥1k events/sec)
    - Time-based queries for temporal graph construction
    - Delta compaction for storage efficiency
    - Protobuf serialization compatibility
    - Batch operations for training data preparation

Author: NERRF Team
License: AGPL v3
"""

import json
import logging
import struct
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

try:
    import rocksdb
    ROCKSDB_AVAILABLE = True
except ImportError:
    ROCKSDB_AVAILABLE = False
    # Create dummy class for environments without RocksDB
    class rocksdb:
        @staticmethod
        def open(*args, **kwargs):
            raise ImportError("RocksDB not installed. Install with: pip install rocksdb")
from google.protobuf.timestamp_pb2 import Timestamp

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class RocksDBEventStore:
    """
    High-performance event storage using RocksDB.
    
    Key Design:
        - Time-prefixed keys for efficient range queries
        - Protobuf serialization for schema compatibility
        - Column families for different data types
        - Configurable compaction for M1 requirements
    """
    
    def __init__(self, db_path: str, create_if_missing: bool = True):
        """
        Initialize RocksDB connection.
        
        Args:
            db_path: Path to RocksDB database directory
            create_if_missing: Create database if it doesn't exist
        """
        self.db_path = Path(db_path)
        self.db_path.mkdir(parents=True, exist_ok=True)
        
        # RocksDB options optimized for time-series data
        opts = rocksdb.Options()
        opts.create_if_missing = create_if_missing
        opts.max_open_files = 300000
        opts.write_buffer_size = 67108864  # 64MB
        opts.max_write_buffer_number = 3
        opts.target_file_size_base = 67108864  # 64MB
        
        # Enable compression for storage efficiency
        opts.compression = rocksdb.CompressionType.snappy_compression
        
        # Configure compaction for 30-second deltas (M1 requirement)
        opts.compaction_style = rocksdb.CompactionStyle.level_style
        opts.level0_file_num_compaction_trigger = 4
        opts.level0_slowdown_writes_trigger = 20
        opts.level0_stop_writes_trigger = 36
        opts.max_background_compactions = 4
        
        try:
            self.db = rocksdb.DB(str(self.db_path), opts)
            logger.info(f"Opened RocksDB at {self.db_path}")
        except Exception as e:
            logger.error(f"Failed to open RocksDB: {e}")
            raise
    
    def _make_key(self, timestamp: datetime, event_id: str = "") -> bytes:
        """
        Create time-prefixed key for efficient range queries.
        
        Format: timestamp_microseconds + event_id
        This ensures events are stored in chronological order.
        """
        timestamp_us = int(timestamp.timestamp() * 1_000_000)
        key = struct.pack(">Q", timestamp_us)  # Big-endian 8-byte timestamp
        if event_id:
            key += event_id.encode('utf-8')
        return key
    
    def _parse_key(self, key: bytes) -> Tuple[datetime, str]:
        """Parse timestamp and event_id from key."""
        timestamp_us = struct.unpack(">Q", key[:8])[0]
        timestamp = datetime.fromtimestamp(timestamp_us / 1_000_000)
        event_id = key[8:].decode('utf-8') if len(key) > 8 else ""
        return timestamp, event_id
    
    def store_event(self, event_data: Dict, timestamp: Optional[datetime] = None) -> bool:
        """
        Store a single event in RocksDB.
        
        Args:
            event_data: Event dictionary (from protobuf or JSONL)
            timestamp: Event timestamp (uses current time if None)
            
        Returns:
            True if stored successfully
        """
        if timestamp is None:
            timestamp = datetime.now()
        
        try:
            # Create unique key with timestamp + event hash
            event_id = f"{event_data.get('pid', 0)}_{hash(str(event_data)) & 0xFFFFFF}"
            key = self._make_key(timestamp, event_id)
            
            # Serialize event as JSON (could be protobuf in production)
            value = json.dumps(event_data).encode('utf-8')
            
            self.db.put(key, value)
            return True
            
        except Exception as e:
            logger.error(f"Failed to store event: {e}")
            return False
    
    def store_events_batch(self, events: List[Tuple[Dict, datetime]]) -> int:
        """
        Store multiple events in a batch for better performance.
        
        Args:
            events: List of (event_data, timestamp) tuples
            
        Returns:
            Number of events successfully stored
        """
        batch = rocksdb.WriteBatch()
        stored_count = 0
        
        try:
            for event_data, timestamp in events:
                event_id = f"{event_data.get('pid', 0)}_{hash(str(event_data)) & 0xFFFFFF}"
                key = self._make_key(timestamp, event_id)
                value = json.dumps(event_data).encode('utf-8')
                batch.put(key, value)
                stored_count += 1
            
            self.db.write(batch)
            logger.info(f"Stored batch of {stored_count} events")
            return stored_count
            
        except Exception as e:
            logger.error(f"Failed to store batch: {e}")
            return 0
    
    def query_events(self, start_time: datetime, end_time: datetime) -> Iterator[Tuple[datetime, Dict]]:
        """
        Query events within time range.
        
        Args:
            start_time: Start of time range
            end_time: End of time range
            
        Yields:
            (timestamp, event_data) tuples
        """
        start_key = self._make_key(start_time)
        end_key = self._make_key(end_time)
        
        try:
            it = self.db.iteritems()
            it.seek(start_key)
            
            for key, value in it:
                if key > end_key:
                    break
                
                timestamp, _ = self._parse_key(key)
                event_data = json.loads(value.decode('utf-8'))
                yield timestamp, event_data
                
        except Exception as e:
            logger.error(f"Failed to query events: {e}")
    
    def get_event_count(self, start_time: datetime, end_time: datetime) -> int:
        """Get count of events in time range."""
        count = 0
        for _ in self.query_events(start_time, end_time):
            count += 1
        return count
    
    def get_latest_events(self, limit: int = 100) -> List[Tuple[datetime, Dict]]:
        """Get the most recent events."""
        events = []
        
        try:
            it = self.db.iteritems()
            it.seek_to_last()
            
            for i, (key, value) in enumerate(it):
                if i >= limit:
                    break
                
                timestamp, _ = self._parse_key(key)
                event_data = json.loads(value.decode('utf-8'))
                events.append((timestamp, event_data))
            
            # Reverse to get chronological order
            events.reverse()
            
        except Exception as e:
            logger.error(f"Failed to get latest events: {e}")
        
        return events
    
    def compact_db(self):
        """
        Trigger manual compaction (for 30-second delta requirement).
        """
        try:
            self.db.compact_range()
            logger.info("Database compaction completed")
        except Exception as e:
            logger.error(f"Compaction failed: {e}")
    
    def get_stats(self) -> Dict:
        """Get database statistics."""
        try:
            stats = {
                "approximate_size": self.db.get_property(b"rocksdb.estimate-live-data-size"),
                "num_keys": self.db.get_property(b"rocksdb.estimate-num-keys"),
                "mem_table_size": self.db.get_property(b"rocksdb.cur-size-active-mem-table"),
                "block_cache_usage": self.db.get_property(b"rocksdb.block-cache-usage"),
            }
            return stats
        except Exception as e:
            logger.error(f"Failed to get stats: {e}")
            return {}
    
    def close(self):
        """Close database connection."""
        if hasattr(self, 'db'):
            del self.db
            logger.info("RocksDB connection closed")


class EventStreamProcessor:
    """
    Processes real-time event streams for AI training pipeline.
    
    Integrates with M1 tracker gRPC stream and M2 PyTorch dataset.
    """
    
    def __init__(self, db_store: RocksDBEventStore, 
                 window_size: timedelta = timedelta(minutes=5)):
        self.db_store = db_store
        self.window_size = window_size
        self.buffer = []
        self.last_process_time = datetime.now()
    
    def process_protobuf_event(self, pb_event) -> bool:
        """
        Process protobuf event from M1 tracker.
        
        Args:
            pb_event: Protobuf Event object from tracker
            
        Returns:
            True if processed successfully
        """
        try:
            # Convert protobuf to dict
            event_data = {
                "timestamp": pb_event.ts.ToDatetime().isoformat(),
                "pid": pb_event.pid,
                "tid": pb_event.tid,
                "comm": pb_event.comm,
                "syscall": pb_event.syscall,
                "path": pb_event.path,
                "new_path": pb_event.new_path,
                "ret_val": pb_event.ret_val,
                "bytes": pb_event.bytes,
                "flags": str(pb_event.flags)
            }
            
            timestamp = pb_event.ts.ToDatetime()
            return self.db_store.store_event(event_data, timestamp)
            
        except Exception as e:
            logger.error(f"Failed to process protobuf event: {e}")
            return False
    
    def create_training_windows(self, start_time: datetime, 
                              end_time: datetime) -> List[List[Dict]]:
        """
        Create sliding windows for training data.
        
        Args:
            start_time: Start of data range
            end_time: End of data range
            
        Returns:
            List of event windows for PyTorch dataset
        """
        windows = []
        current_start = start_time
        stride = timedelta(minutes=1)  # 1-minute stride
        
        while current_start + self.window_size <= end_time:
            current_end = current_start + self.window_size
            
            # Get events in this window
            window_events = list(self.db_store.query_events(current_start, current_end))
            if window_events:
                # Convert to list of dicts for NERRFDataset
                event_dicts = [event_data for _, event_data in window_events]
                windows.append(event_dicts)
            
            current_start += stride
        
        return windows


def migrate_jsonl_to_rocksdb(jsonl_path: str, db_path: str) -> int:
    """
    Migrate benchmark JSONL data to RocksDB for AI training.
    
    Args:
        jsonl_path: Path to JSONL benchmark file
        db_path: Path to RocksDB database
        
    Returns:
        Number of events migrated
    """
    store = RocksDBEventStore(db_path)
    events = []
    
    try:
        with open(jsonl_path, 'r') as f:
            for line in f:
                data = json.loads(line.strip())
                timestamp = datetime.fromisoformat(data["timestamp"].replace('Z', '+00:00'))
                events.append((data, timestamp))
        
        # Store in batches for better performance
        batch_size = 1000
        total_stored = 0
        
        for i in range(0, len(events), batch_size):
            batch = events[i:i + batch_size]
            stored = store.store_events_batch(batch)
            total_stored += stored
            
            if i % 10000 == 0:
                logger.info(f"Migrated {total_stored} events...")
        
        logger.info(f"Migration complete: {total_stored} events")
        store.close()
        return total_stored
        
    except Exception as e:
        logger.error(f"Migration failed: {e}")
        return 0


if __name__ == "__main__":
    # Production usage example:
    # store = RocksDBEventStore("/data/nerrf_events.db")
    # store.store_event(event_dict)
    # events = list(store.query_events(start_time, end_time))
    pass