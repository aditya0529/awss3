import boto3
import os
import traceback

s3 = boto3.client("s3")
secrets = boto3.client("secretsmanager")

SECRET_NAME = os.environ["SECRET_NAME"]
PASSWORD_SECRET_NAME = os.environ["PASSWORD_SECRET_ARN"]
CLIENT_SECRET_NAME = os.environ["CLIENT_SECRET_ARN"]


def handler(event, context):
    print(f'Incoming event : {event}')
    for record in event["Records"]:
        try:
            bucket = record["s3"]["bucket"]["name"]
            key = record["s3"]["object"]["key"]

            tmp_path = f"/tmp/{os.path.basename(key)}"
            s3.download_file(bucket, key, tmp_path)

            with open(tmp_path, "r") as f:
                data = f.read()

            #secret_name = SECRET_NAME if key.endswith("jks") else PASSWORD_SECRET_NAME
            if key.endswith(".jks"):
                secret_name = SECRET_NAME
            elif key == "keystore.password":
                secret_name = PASSWORD_SECRET_NAME
            elif key == "client.password":
                secret_name = CLIENT_SECRET_NAME
            else:
                error_msg = f"Unsupported key: {key}. Must end with '.jks' or be 'keystore.password' or 'client.password'"
                print(error_msg)
                raise ValueError(error_msg)

            secrets.put_secret_value(
                SecretId=secret_name,
                SecretString=data
            )
            print(f"Updated secret {secret_name} with {key}")
            os.remove(tmp_path)
        except Exception as e:
            print(f"Unexpected error processing record: {e}")
            traceback.print_exc()
