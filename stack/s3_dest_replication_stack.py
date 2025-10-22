from constructs import Construct
from aws_cdk import (
    Duration,
    Stack,
    RemovalPolicy,
    aws_s3 as s3,
    aws_iam as iam
)


class S3destinationStack(Stack):
    def create_destination_s3_policy(self, s3_bucket_arn: str, second_region: str) -> dict:
        """
        Create bucket policy for destination bucket.
        Restricts replication to only objects with second_region/* prefix.
        """
        return {
            "Action": [
                "s3:ReplicateObject",
                "s3:ReplicateDelete",
                "s3:ReplicateTags"
            ],
            "Effect": "Allow",
            "Resource": [
                f"{s3_bucket_arn}/{second_region}/*"
            ],
            "Principal": {"Service": "s3.amazonaws.com"},
            "Sid": "AllowReplicationOfSecondRegionObjects"
        }

    def create_bucket(self, bucket_id: str, bucket_name: str, config):
        """Helper method to create a destination bucket with standard configuration"""
        bucket = s3.Bucket(self,
                           id=bucket_id,
                           bucket_name=bucket_name,
                           block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
                           encryption=s3.BucketEncryption.S3_MANAGED,
                           minimum_tls_version=1.2,
                           object_ownership=s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
                           object_lock_enabled=True,
                           removal_policy=RemovalPolicy.RETAIN,  # Required for object lock
                           enforce_ssl=True,
                           versioned=True,
                           lifecycle_rules=[s3.LifecycleRule(
                               enabled=True,
                               id=f"{bucket_id}-lifecycle",
                               noncurrent_version_expiration=Duration.days(124),
                               noncurrent_versions_to_retain=5
                           )]
                           )
        
        # Add replication policy - only allow replication of second_region/* objects
        replication_policy = self.create_destination_s3_policy(
            s3_bucket_arn=bucket.bucket_arn,
            second_region=config['second_region']
        )
        policy_statement = iam.PolicyStatement.from_json(replication_policy)
        bucket.add_to_resource_policy(policy_statement)

        # Add Object Lock configuration using CfnBucket
        cfn_bucket = bucket.node.default_child
        cfn_bucket.object_lock_configuration = {
            "objectLockEnabled": "Enabled"
        }
        
        return bucket

    def __init__(self, scope: Construct, construct_id: str, resource_config, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Get configuration variables from resource file
        config = resource_config
        
        # Create first destination bucket (regular)
        self.bucket_1 = self.create_bucket(
            bucket_id=f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}-secrets-s3-dest-{config['resource_suffix']}",
            bucket_name=f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}-secrets-s3-{config['second_region']}-{config['resource_suffix']}",
            config=config
        )
        
        # # Create second destination bucket (temp)
        # self.bucket_2 = self.create_bucket(
        #     bucket_id=f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}-secrets-s3-dest-temp-{config['resource_suffix']}",
        #     bucket_name=f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}-secrets-s3-{config['second_region']}-{config['resource_suffix']}-temp",
        #     config=config
        # )