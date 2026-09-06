import os
import uuid
from typing import Tuple

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from config import settings

UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)


def is_r2_configured() -> bool:
    """Check if Cloudflare R2 credentials are provided."""
    return bool(
        settings.CF_ACCOUNT_ID
        and settings.CF_ACCESS_KEY_ID
        and settings.CF_SECRET_ACCESS_KEY
        and settings.CF_ACCOUNT_ID.strip()
    )


def _get_client():
    """Create and return a boto3 S3 client configured for Cloudflare R2."""
    return boto3.client(
        "s3",
        endpoint_url=f"https://{settings.CF_ACCOUNT_ID}.r2.cloudflarestorage.com",
        aws_access_key_id=settings.CF_ACCESS_KEY_ID,
        aws_secret_access_key=settings.CF_SECRET_ACCESS_KEY,
        config=Config(signature_version="s3v4"),
        region_name="auto",
    )


def upload_file(file_bytes: bytes, filename: str, content_type: str) -> Tuple[str, str]:
    """Upload *file_bytes* to R2 (or local fallback) under a unique key."""
    ext = filename.rsplit(".", 1)[-1] if "." in filename else "bin"
    file_id = f"{uuid.uuid4().hex}.{ext}"

    if is_r2_configured():
        file_key = f"files/{file_id}"
        client = _get_client()
        client.put_object(
            Bucket=settings.CF_BUCKET_NAME,
            Key=file_key,
            Body=file_bytes,
            ContentType=content_type,
        )
        public_url = f"{settings.CF_PUBLIC_URL.rstrip('/')}/{file_key}"
        return file_key, public_url
    else:
        # Local storage fallback
        local_path = os.path.join(UPLOAD_DIR, file_id)
        with open(local_path, "wb") as f:
            f.write(file_bytes)
        return file_id, f"/local/{file_id}"


def get_local_file_path(file_key: str) -> str:
    """Return local path for a stored file."""
    # handle both "files/xxx" or "xxx"
    filename = os.path.basename(file_key)
    return os.path.join(UPLOAD_DIR, filename)


def delete_file(file_key: str) -> None:
    """Delete the object identified by *file_key* from R2 or local disk."""
    if is_r2_configured():
        client = _get_client()
        try:
            client.delete_object(Bucket=settings.CF_BUCKET_NAME, Key=file_key)
        except ClientError as exc:
            error_code = exc.response.get("Error", {}).get("Code", "")
            if error_code not in ("NoSuchKey", "404"):
                raise
    else:
        local_path = get_local_file_path(file_key)
        if os.path.exists(local_path):
            try:
                os.remove(local_path)
            except OSError:
                pass


def generate_presigned_url(file_key: str, expires: int = 3600) -> str:
    """Return a pre-signed GET URL for *file_key* that is valid for *expires* seconds."""
    if not is_r2_configured():
        return f"/api/files/download/{file_key}"
    client = _get_client()
    url: str = client.generate_presigned_url(
        "get_object",
        Params={"Bucket": settings.CF_BUCKET_NAME, "Key": file_key},
        ExpiresIn=expires,
    )
    return url
