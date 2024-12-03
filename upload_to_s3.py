import sys
import boto3
import os

def upload_to_s3(file_path):
    s3 = boto3.client('s3')
    bucket_name = os.getenv('S3_BUCKET_NAME')
    s3.upload_file(file_path, bucket_name, os.path.basename(file_path))
    print(f"Uploaded {file_path} to {bucket_name}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python upload_to_s3.py <file_path>")
        sys.exit(1)
    upload_to_s3(sys.argv[1])
