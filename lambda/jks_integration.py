import boto3
import os
import traceback
from botocore.exceptions import ClientError

s3 = boto3.client("s3")
secrets = boto3.client("secretsmanager")

SECRET_NAME = os.environ["SECRET_NAME"]
PASSWORD_SECRET_NAME = os.environ["PASSWORD_SECRET_ARN"]
CLIENT_SECRET_NAME = os.environ["CLIENT_SECRET_ARN"]
CURRENT_REGION = os.environ["AWS_REGION"]


def extract_region_from_path(s3_key):
    """
    Extract region from S3 key path.
    Expected format: {region}/filename.ext
    Example: eu-west-1/keystore.jks → returns 'eu-west-1'
    """
    parts = s3_key.split('/', 1)
    if len(parts) == 2:
        return parts[0]
    return None


def delete_all_versions_of_object(bucket_name, object_key):

    try:
        print(f"Delete the object from the S3 bucket..")

        versions = s3.list_object_versions(Bucket=bucket_name, Prefix=object_key)
        delete_items = []

        for version in versions.get('Versions', []):
            delete_items.append({'Key': version['Key'], 'VersionId': version['VersionId']})
        for marker in versions.get('DeleteMarkers', []):
            delete_items.append({'Key': marker['Key'], 'VersionId': marker['VersionId']})

        if delete_items:
            response = s3.delete_objects(Bucket=bucket_name, Delete={'Objects': delete_items})
            print(f"Deleted versions of object '{object_key}' from bucket '{bucket_name}':")
            for deleted in response.get('Deleted', []):
                print(f"  - Key: {deleted['Key']}, VersionId: {deleted['VersionId']}")
        else:
            print(f"No versions found for object '{object_key}' in bucket '{bucket_name}'.")
    except ClientError as e:
        print(f"Error deleting versions of object '{object_key}': {e}")


def handler(event, context):
    print(f'Incoming event: {event}')
    print(f'Lambda running in region: {CURRENT_REGION}')
    
    for record in event["Records"]:
        try:
            bucket = record["s3"]["bucket"]["name"]
            key = record["s3"]["object"]["key"]
            
            print(f'Processing S3 key: {key} from bucket: {bucket}')
            
            # Extract region from path (e.g., "eu-west-1/keystore.jks" → "eu-west-1")
            file_region = extract_region_from_path(key)
            
            if not file_region:
                print(f'WARNING: Skipping {key} - no region prefix found. Expected format: {{region}}/filename.ext')
                continue
            
            # Only process if file region matches Lambda's current region
            if file_region != CURRENT_REGION:
                print(f'Skipping {key}: file region "{file_region}" != Lambda region "{CURRENT_REGION}"')
                continue
            
            print(f'File region matches Lambda region ({CURRENT_REGION}). Processing...')
            
            # Extract filename without region prefix (e.g., "eu-west-1/keystore.jks" → "keystore.jks")
            filename = key.split('/', 1)[1] if '/' in key else key
            print(f'Extracted filename: {filename}')
            
            # Download file
            tmp_path = f"/tmp/{os.path.basename(filename)}"
            s3.download_file(bucket, key, tmp_path)

            with open(tmp_path, "r") as f:
                data = f.read()

            # Determine which secret to update based on filename
            if filename.endswith(".jks"):
                secret_name = SECRET_NAME
                secret_type = "JKS keystore"
            elif filename == "keystore.password":
                secret_name = PASSWORD_SECRET_NAME
                secret_type = "keystore password"
            elif filename == "client.password":
                secret_name = CLIENT_SECRET_NAME
                secret_type = "client password"
            else:
                error_msg = f"Unsupported filename: {filename}. Must be: *.jks, keystore.password, or client.password"
                print(error_msg)
                raise ValueError(error_msg)

            # Update secret
            secrets.put_secret_value(
                SecretId=secret_name,
                SecretString=data
            )
            print(f'✓ Successfully updated {secret_type} secret ({secret_name}) with content from {key}')
            
            # Cleanup
            os.remove(tmp_path)

            # Delete the object from the S3 bucket
            delete_all_versions_of_object(bucket, key)

        except Exception as e:
            print(f"ERROR processing record: {e}")
            traceback.print_exc()
