from constructs import Construct
from aws_cdk import (
    Duration,
    Stack,
    RemovalPolicy,
    aws_s3 as s3,
    aws_iam as iam
)


class S3destinationStack(Stack):
    def create_destination_s3_policy(self, s3_bucket_arn: str) -> dict:
        return {
            "Action": [
                "s3:ReplicateObject"
            ],
            "Effect": "Allow",
            "Resource": [
                f"{s3_bucket_arn}",
                f"{s3_bucket_arn}/*"
            ],
            "Principal": iam.ServicePrincipal("s3.amazonaws.com"),
            "Sid": "AllowAccessToStoreObjects"
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
        
        policy_statement = iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=["s3:GetObject"],
            resources=[bucket.bucket_arn + "/*"],
            principals=[iam.ServicePrincipal("s3.amazonaws.com")]
        )
        bucket.add_to_resource_policy(policy_statement)

        self._add_bucket_file_policies(bucket, config)

        # Add Object Lock configuration using CfnBucket
        cfn_bucket = bucket.node.default_child
        cfn_bucket.object_lock_configuration = {
            "objectLockEnabled": "Enabled"
        }
        
        return bucket
    
    def _add_bucket_file_policies(self, bucket: s3.Bucket, config) -> None:

        current_region = self.region
        
        # Build Lambda role ARN dynamically
        lambda_role_arn = (
            f"arn:aws:iam::{config['workload_account']}:role/"
            f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-"
            f"ptapii-secret-lambda-role-{current_region}-{config['resource_suffix']}"
        )
        
        # Policy 1: ALLOW Lambda role to access files
        allow_policy_json = {
            "Sid": "AllowLambdaAccessToSensitiveFiles",
            "Effect": "Allow",
            "Principal": {"AWS": lambda_role_arn},
            "Action": "s3:GetObject",
            "Resource": [
                f"{bucket.bucket_arn}/{current_region}/.jks",
                f"{bucket.bucket_arn}/{current_region}/*.password"
            ]
        }
        allow_policy = iam.PolicyStatement.from_json(allow_policy_json)
        
        # Policy 2: DENY everyone else access to sensitive files
        deny_policy = iam.PolicyStatement(
            sid="DenyAllOthersAccessToSensitiveFiles",
            effect=iam.Effect.DENY,
            principals=[iam.AnyPrincipal()],
            actions=["s3:GetObject"],
            resources=[
                f"{bucket.bucket_arn}/{current_region}/.jks",
                f"{bucket.bucket_arn}/{current_region}/*.password"
            ],
            conditions={
                "StringNotLike": {
                    "aws:PrincipalArn": lambda_role_arn
                }
            }
        )
        
        # Add both policies to bucket
        bucket.add_to_resource_policy(allow_policy)
        bucket.add_to_resource_policy(deny_policy)

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
