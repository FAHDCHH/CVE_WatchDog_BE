"""
storage/s3.py
S3 write operations — boto3 lives here only.
"""
import boto3
from core.config import settings


def get_s3_client():
    """Create and return an S3 client configured for Cloudflare R2."""
    return boto3.client(
        "s3",
        endpoint_url=settings.R2_PL_URL,
        aws_access_key_id=settings.R2_EXTRACTOR_KEY,
        aws_secret_access_key=settings.R2_EXTRACTOR_SECRECT_KEY,
        region_name="auto",
    )


def build_s3_key(
    source: str, date: str, run_id: str, suffix: str = "snapshot"
) -> str:
    """
    Build a Hive-style partitioned S3 key.
    Example: raw/epss_scores/year=2026/month=04/day=17/run_{id}_snapshot.parquet
    """
    return (
        f"raw/{source}/"
        f"year={date[:4]}/month={date[5:7]}/day={date[8:10]}/"
        f"run_{run_id}_{suffix}.parquet"
    )


def upload_parquet(bytes_data: bytes, s3_key: str) -> None:
    """Upload Parquet bytes to R2. Raises on failure — caller handles errors."""
    client = get_s3_client()
    client.put_object(
        Bucket=settings.R2_BUCKET_NAME,
        Key=s3_key,
        Body=bytes_data,
    )
