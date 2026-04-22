"""
storage/parquet.py
Parquet serialization and deserialization.
"""
import pyarrow as pa
import pyarrow.parquet as pq
import io

def to_parquet_bytes(records: list[dict]) -> bytes:
    """
    Convert a list of dictionaries to Parquet bytes.
    """
    table = pa.Table.from_pylist(records)
    buffer = io.BytesIO()
    pq.write_table(table, buffer)
    return buffer.getvalue()


