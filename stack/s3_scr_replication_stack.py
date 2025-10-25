from constructs import Construct
from aws_cdk import (
    Duration,
    Stack,
    RemovalPolicy,
    aws_s3 as s3,
    aws_iam as iam
)


class S3SourceStack(Stack):

    @staticmethod
    def _get_common_bucket_props() -> dict:
        """ Common bucket properties """
        return {
            'block_public_access': s3.BlockPublicAccess.BLOCK_ALL,
            'encryption': s3.BucketEncryption.S3_MANAGED,
            'minimum_tls_version': 1.2,
            'object_ownership': s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
            'object_lock_enabled': True,
            'removal_policy': RemovalPolicy.RETAIN,
            'enforce_ssl': True,
            'versioned': True
        }
    
    def create_source_s3_policy(self, s3_bucket_arn: str, s3_dest_bucket_arn: str) -> list:
        """
        Parameters
        ----------
        s3_bucket_arn : str
            S3 resource arn

        Returns
        -------
        dict
            IAM policy statement with specific permission
        """
        return [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:GetObjectVersionForReplication",
                    "s3:GetObjectVersionAcl",
                    "s3:GetObjectVersionTagging"
                ],
                "Resource": [f"{s3_bucket_arn}/*"]
            },
            {
                "Effect": "Allow",
                "Action": [
                    "s3:ListBucket",
                    "s3:GetReplicationConfiguration"
                ],
                "Resource": [f"{s3_bucket_arn}"]
            },
            {
                "Effect": "Allow",
                "Action": [
                    "s3:ReplicateObject",
                    "s3:ReplicateDelete",
                    "s3:ReplicateTags"
                ],
                "Resource": [f"{s3_dest_bucket_arn}/*"]
            }
        ]

    def create_source_bucket_with_replication(self, bucket_id: str, bucket_name: str, dest_bucket_name: str, 
                                             replication_role: iam.Role, config, suffix: str = "-replication"):

        props = self._get_common_bucket_props()
        
        # Create S3 bucket
        bucket = s3.Bucket(
            self,
            id=bucket_id,
            bucket_name=bucket_name,
            lifecycle_rules=[s3.LifecycleRule(
                enabled=True,
                id=f"{bucket_id}-lifecycle{suffix}",
                noncurrent_version_expiration=Duration.days(124),
                noncurrent_versions_to_retain=5
            )],
            **props
        )

        # Add Object Lock configuration
        cfn_bucket = bucket.node.default_child
        cfn_bucket.object_lock_configuration = {
            "objectLockEnabled": "Enabled"
        }

        # Add bucket policy
        policy_statement = iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=["s3:GetObject"],
            resources=[bucket.bucket_arn + "/*"],
            principals=[iam.ServicePrincipal("s3.amazonaws.com")]
        )
        bucket.add_to_resource_policy(policy_statement)
        
        # Add security policies for sensitive files (.jks/.password)
        self._add_bucket_file_policies(bucket, config)

        replication_rule_dict = {
            "Destination": {
                "Bucket": f"arn:aws:s3:::{dest_bucket_name}",
                "AccessControlTranslation": {
                    "Owner": "Destination"
                },
                "Account": f"{config['workload_account']}",
                "ReplicationTime": {
                    "Status": "Enabled",
                    "Time": {
                        "Minutes": 15
                    }
                },
                "Metrics": {
                    "Status": "Enabled",
                    "EventThreshold": {
                        "Minutes": 15
                    }
                }
            },
            "Status": "Enabled",
            "Priority": 1,
            "DeleteMarkerReplication": {
                "Status": "Enabled"
            },
            "Filter": {
                "Prefix": f"{config['second_region']}/"
            }
        }
        
        cfn_bucket.add_property_override(
            "ReplicationConfiguration.Role", replication_role.role_arn)
        cfn_bucket.add_property_override(
            "ReplicationConfiguration.Rules", [replication_rule_dict])
        
        return bucket

    def create_source_bucket_without_replication(self, bucket_id: str, bucket_name: str, config, suffix: str = "-simple") -> s3.Bucket:

        props = self._get_common_bucket_props()
        
        bucket = s3.Bucket(
            self,
            id=bucket_id,
            bucket_name=bucket_name,
            lifecycle_rules=[s3.LifecycleRule(
                enabled=True,
                id=f"{bucket_id}-lifecycle{suffix}",  # Use suffix to differentiate
                noncurrent_version_expiration=Duration.days(124),
                noncurrent_versions_to_retain=5
            )],
            **props
        )
        
        # Configure Object Lock
        cfn_bucket = bucket.node.default_child
        cfn_bucket.object_lock_configuration = {"objectLockEnabled": "Enabled"}
        
        # Add standard bucket policy
        bucket.add_to_resource_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["s3:GetObject"],
                resources=[f"{bucket.bucket_arn}/*"],
                principals=[iam.ServicePrincipal("s3.amazonaws.com")]
            )
        )

        self._add_bucket_file_policies(bucket, config)
        
        return bucket
    
    def _create_replication_role(self, config, source_bucket_arn: str, dest_bucket_arn: str) -> iam.Role:

        role = iam.Role(
            self,
            f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}-replication-role-{config['resource_suffix']}",
            assumed_by=iam.ServicePrincipal("s3.amazonaws.com"),
            role_name=f"{config['resource_prefix']}-{config['service_name']}-report-replication-role-{config['resource_suffix']}"
        )
        
        # Apply policies
        for policy_json in self.create_source_s3_policy(source_bucket_arn, dest_bucket_arn):
            role.add_to_policy(iam.PolicyStatement.from_json(policy_json))
        
        return role
    
    def _add_bucket_file_policies(self, bucket: s3.Bucket, config) -> None:


        current_region = self.region
        
        # Build Lambda role ARN dynamically
        lambda_role_arn = (
            f"arn:aws:iam::{config['workload_account']}:role/"
            f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-"
            f"ptapii-secret-lambda-role-{current_region}-{config['resource_suffix']}"
        )
        
        # ALLOW Lambda role to access files
        allow_policy = iam.PolicyStatement(
            sid="AllowLambdaAccessToSensitiveFiles",
            effect=iam.Effect.ALLOW,
            principals=[iam.ArnPrincipal(lambda_role_arn)],
            actions=["s3:GetObject"],
            resources=[
                f"{bucket.bucket_arn}/{current_region}/.jks",
                f"{bucket.bucket_arn}/{current_region}/*.password"
            ]
        )
        
        # DENY everyone else access to sensitive files
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

    def __init__(self, scope: Construct, construct_id: str, resource_config, enable_replication: bool = True, **kwargs) -> None:

        super().__init__(scope, construct_id, **kwargs)

        config = resource_config
        
        # Generate bucket names
        bucket_id = f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}-secrets-s3-{config['resource_suffix']}"
        bucket_name = f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}-secrets-s3-{config['first_region']}-{config['resource_suffix']}"
        
        if enable_replication:
            # Multi-region:
            dest_bucket_name = f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}-secrets-s3-{config['second_region']}-{config['resource_suffix']}"
            
            # Create replication role first
            replication_role = self._create_replication_role(
                config=config,
                source_bucket_arn=f"arn:aws:s3:::{bucket_name}",  # Use bucket name for ARN
                dest_bucket_arn=f"arn:aws:s3:::{dest_bucket_name}"
            )
            
            # Create source bucket WITH replication (complete solution)
            self.bucket_1 = self.create_source_bucket_with_replication(
                bucket_id=bucket_id,
                bucket_name=bucket_name,
                dest_bucket_name=dest_bucket_name,
                replication_role=replication_role,
                config=config
            )
        else:
            # Single-region: Create source bucket WITHOUT replication
            self.bucket_1 = self.create_source_bucket_without_replication(bucket_id, bucket_name, config)
