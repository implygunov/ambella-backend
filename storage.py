import uuid
from typing import Tuple

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from config import settings


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
    """Upload *file_bytes* to R2 under a unique key derived from *filename*.

    Returns:
        (file_key, public_url) where file_key is the R2 object key and
        public_url is the publicly accessible URL for the object.
    """
    ext = filename.rsplit(".", 1)[-1] if "." in filename else "bin"
    file_key = f"files/{uuid.uuid4().hex}.{ext}"

    client = _get_client()
    client.put_object(
        Bucket=settings.CF_BUCKET_NAME,
        Key=file_key,
        Body=file_bytes,
        ContentType=content_type,
    )

    public_url = f"{settings.CF_PUBLIC_URL.rstrip('/')}/{file_key}"
    return file_key, public_url


def delete_file(file_key: str) -> None:
    """Delete the object identified by *file_key* from R2.

    Silently ignores NoSuchKey errors so callers need not check existence first.
    """
    client = _get_client()
    try:
        client.delete_object(Bucket=settings.CF_BUCKET_NAME, Key=file_key)
    except ClientError as exc:
        error_code = exc.response.get("Error", {}).get("Code", "")
        if error_code not in ("NoSuchKey", "404"):
            raise


def generate_presigned_url(file_key: str, expires: int = 3600) -> str:
    """Return a pre-signed GET URL for *file_key* that is valid for *expires* seconds.

    This is useful when the bucket is private and direct downloads must be
    time-limited.
    """
    client = _get_client()
    url: str = client.generate_presigned_url(
        "get_object",
        Params={"Bucket": settings.CF_BUCKET_NAME, "Key": file_key},
        ExpiresIn=expires,
    )
    return url
