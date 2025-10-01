from constructs import Construct
from aws_cdk import (
    Duration,
    Stack,
    RemovalPolicy,
    aws_s3 as s3,
    aws_iam as iam
)


class S3SourceStack(Stack):
    def create_source_s3_policy(self, s3_bucket_arn: str,s3_dest_bucket_arn: str) -> list:
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

    def create_source_bucket(self, bucket_id: str, bucket_name: str, dest_bucket_name: str, 
                            replication_role: iam.Role, config, suffix: str = ""):
        """Helper method to create a source bucket with replication configuration"""
        
        # Create S3 bucket
        bucket = s3.Bucket(self,
                           id=bucket_id,
                           bucket_name=bucket_name,
                           block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
                           encryption=s3.BucketEncryption.S3_MANAGED,
                           minimum_tls_version=1.2,
                           object_ownership=s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
                           object_lock_enabled=True,
                           removal_policy=RemovalPolicy.RETAIN,
                           enforce_ssl=True,
                           versioned=True,
                           lifecycle_rules=[s3.LifecycleRule(
                               enabled=True,
                               id=f"{bucket_id}-lifecycle",
                               noncurrent_version_expiration=Duration.days(124),
                               noncurrent_versions_to_retain=5
                           )]
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

        # Configure replication
        replication_rule_dict = {
            "Destination": {
                "Bucket": f"arn:aws:s3:::{dest_bucket_name}",
                "AccessControlTranslation": {
                    "Owner": "Destination"
                },
                "Account": f"{config['s3_replication_account']}",
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
            "DeleteMarkerReplication": {
                "Status": "Enabled"
            },
            "Priority": 1
        }
        
        # Add filter only if prefix is not empty
        if config.get('s3_filter_prefix', '').strip():
            replication_rule_dict["Filter"] = {
                "Prefix": f"{config['s3_filter_prefix']}"
            }
        
        cfn_bucket.add_property_override(
            "ReplicationConfiguration.Role", replication_role.role_arn)
        cfn_bucket.add_property_override(
            "ReplicationConfiguration.Rules", [replication_rule_dict])
        
        return bucket

    def __init__(self, scope: Construct, construct_id: str, resource_config, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        config = resource_config

        # Create replication role both buckets
        replication_role = iam.Role(self,
                                    f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}-replication-role-{config['resource_suffix']}",
                                    assumed_by=iam.ServicePrincipal("s3.amazonaws.com"),
                                    role_name=f"{config['resource_prefix']}-{config['service_name']}-report-replication-role-{config['resource_suffix']}"
                                    )
        
        # Add policies for first bucket pair
        for statement_json in self.create_source_s3_policy(
                s3_bucket_arn=f"arn:aws:s3:::{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}-secrets-s3-{config['first_region']}-{config['resource_suffix']}",
                s3_dest_bucket_arn=f"arn:aws:s3:::{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}-secrets-s3-{config['second_region']}-{config['resource_suffix']}"):
            policy_statement = iam.PolicyStatement.from_json(statement_json)
            replication_role.add_to_policy(policy_statement)
        
        # Add policies for second bucket pair (temp)
        for statement_json in self.create_source_s3_policy(
                s3_bucket_arn=f"arn:aws:s3:::{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}-secrets-s3-{config['first_region']}-{config['resource_suffix']}-temp",
                s3_dest_bucket_arn=f"arn:aws:s3:::{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}-secrets-s3-{config['second_region']}-{config['resource_suffix']}-temp"):
            policy_statement = iam.PolicyStatement.from_json(statement_json)
            replication_role.add_to_policy(policy_statement)

        # Create first source bucket (regular)
        self.bucket_1 = self.create_source_bucket(
            bucket_id=f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}-secrets-s3-src-{config['resource_suffix']}",
            bucket_name=f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}-secrets-s3-{config['first_region']}-{config['resource_suffix']}",
            dest_bucket_name=f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}-secrets-s3-{config['second_region']}-{config['resource_suffix']}",
            replication_role=replication_role,
            config=config
        )
        
        # Create second source bucket (temp)
        self.bucket_2 = self.create_source_bucket(
            bucket_id=f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}-secrets-s3-src-temp-{config['resource_suffix']}",
            bucket_name=f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}-secrets-s3-{config['first_region']}-{config['resource_suffix']}-temp",
            dest_bucket_name=f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}-secrets-s3-{config['second_region']}-{config['resource_suffix']}-temp",
            replication_role=replication_role,
            config=config,
            suffix="-temp"
        )