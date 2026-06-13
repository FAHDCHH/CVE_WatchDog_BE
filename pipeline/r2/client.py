import csv
import hashlib
import json
from collections.abc import Iterator

import boto3
from botocore.exceptions import ClientError

from core.exceptions.exceptions import R2ReadError, R2WriteError


class R2Client:
    def __init__(
        self,
        bucket_name: str,
        endpoint_url: str,
        access_key_id: str,
        secret_access_key: str,
    ):
        self.bucket_name = bucket_name
        self.client = boto3.client(
            "s3",
            endpoint_url=endpoint_url,
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name="auto",
        )

    def read_json(self, key: str) -> dict:
        try:
            return json.loads(self.read_bytes(key).decode("utf-8"))
        except R2ReadError:
            raise
        except Exception as exc:
            raise R2ReadError(f"Failed to decode JSON object: {key}") from exc

    def read_csv_lines(self, key: str) -> Iterator[dict]:
        try:
            response = self.client.get_object(Bucket=self.bucket_name, Key=key)
            lines = (
                line.decode("utf-8")
                for line in response["Body"].iter_lines()
                if line
            )
            yield from csv.DictReader(lines)
        except Exception as exc:
            raise R2ReadError(f"Failed to read CSV object: {key}") from exc

    def list_keys(self, prefix: str) -> list[str]:
        """Return all object keys under a prefix (paginated, sorted)."""
        try:
            keys: list[str] = []
            token = None
            while True:
                kwargs = {"Bucket": self.bucket_name, "Prefix": prefix}
                if token:
                    kwargs["ContinuationToken"] = token
                response = self.client.list_objects_v2(**kwargs)
                keys.extend(obj["Key"] for obj in response.get("Contents", []))
                if not response.get("IsTruncated"):
                    break
                token = response.get("NextContinuationToken")
            return sorted(keys)
        except Exception as exc:
            raise R2ReadError(f"Failed to list objects: {prefix}") from exc

    def read_bytes(self, key: str) -> bytes:
        try:
            response = self.client.get_object(Bucket=self.bucket_name, Key=key)
            return response["Body"].read()
        except Exception as exc:
            raise R2ReadError(f"Failed to read object: {key}") from exc

    def write_json(self, key: str, data: dict | list) -> str:
        try:
            self.write_bytes(
                key,
                json.dumps(data, separators=(",", ":"), default=str).encode("utf-8"),
                content_type="application/json",
            )
            return key
        except R2WriteError:
            raise
        except Exception as exc:
            raise R2WriteError(f"Failed to write JSON object: {key}") from exc

    def write_bytes(
        self,
        key: str,
        data: bytes,
        content_type: str = "application/octet-stream",
    ) -> str:
        try:
            self.client.put_object(
                Bucket=self.bucket_name,
                Key=key,
                Body=data,
                ContentType=content_type,
            )
            return key
        except Exception as exc:
            raise R2WriteError(f"Failed to write object: {key}") from exc

    def content_hash(self, key: str) -> str:
        try:
            response = self.client.get_object(Bucket=self.bucket_name, Key=key)
            digest = hashlib.sha256()
            body = response["Body"]
            for chunk in iter(lambda: body.read(1024 * 1024), b""):
                digest.update(chunk)
            return digest.hexdigest()
        except Exception as exc:
            raise R2ReadError(f"Failed to hash object: {key}") from exc

    def key_exists(self, key: str) -> bool:
        try:
            self.client.head_object(Bucket=self.bucket_name, Key=key)
            return True
        except ClientError as exc:
            code = str(exc.response.get("Error", {}).get("Code", ""))
            if code in {"404", "NoSuchKey", "NotFound"}:
                return False
            raise R2ReadError(f"Failed to check object existence: {key}") from exc
        except Exception as exc:
            raise R2ReadError(f"Failed to check object existence: {key}") from exc
