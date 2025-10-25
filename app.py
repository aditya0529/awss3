#!/usr/bin/env python3

import configparser
import aws_cdk as cdk
import os
from aws_cdk import (
    Aspects,
    Tags,
)
from cdk_nag import AwsSolutionsChecks, NagSuppressions
from stack.cloud_infra import cloud_infra
from stack.s3_dest_replication_stack import S3destinationStack
from stack.s3_scr_replication_stack import S3SourceStack

def get_def_stack_synth(config, region):
    return cdk.DefaultStackSynthesizer(
        cloud_formation_execution_role=f"arn:aws:iam::{config['workload_account']}:role/{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}dply-role-main-a",
        deploy_role_arn=f"arn:aws:iam::{config['workload_account']}:role/{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}dply-role-main-a",
        file_asset_publishing_role_arn=f"arn:aws:iam::{config['workload_account']}:role/{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}dply-role-main-a",
        image_asset_publishing_role_arn=f"arn:aws:iam::{config['workload_account']}:role/{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}dply-role-main-a",
        lookup_role_arn=f"arn:aws:iam::{config['workload_account']}:role/{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}dply-role-main-a",
        file_assets_bucket_name=f"{config['asset_prefix']}-{config['workload_account']}-{region}-{config['resource_suffix']}",
        bootstrap_stack_version_ssm_parameter=f"{config['bootstrap_stack_version']}"
    )

def apply_tags(stack, config):
    """Apply standard tags to a stack"""
    Tags.of(stack).add("sw:application", f"{config['app_name']}")
    Tags.of(stack).add("sw:product", f"{config['service_name']}")
    Tags.of(stack).add("sw:environment", f"{config['app_env']}")
    Tags.of(stack).add("sw:cost_center", f"{config['cost_center']}")

def get_deployment_regions(config) -> list:
    return [r.strip() for r in config['deployment_regions'].split(",")]

def should_enable_replication(config) -> bool:
    return len(get_deployment_regions(config)) > 1

def create_s3_stacks(app, config, synthesizer_factory):

    enable_replication = should_enable_replication(config)
    stacks = {}
    
    if enable_replication:

        if 'second_region' not in config:
            raise ValueError("'second_region' required for multi-region deployment")
        if 'app_infra_replication_stack_name' not in config:
            raise ValueError("'app_infra_replication_stack_name' required for replication")
            
        # Multi-region: Create destination stack first
        dest_stack = S3destinationStack(
            app,
            f"{config['app_infra_replication_stack_name']}",
            resource_config=config,
            env=cdk.Environment(
                account=config['workload_account'],
                region=config['second_region']
            ),
            synthesizer=synthesizer_factory(config, config['second_region'])
        )
        apply_tags(dest_stack, config)
        stacks['destination'] = dest_stack
    
    # Always create source stack with or without replication
    source_stack = S3SourceStack(
        app,
        f"{config['app_infra_stack_name']}",
        resource_config=config,
        enable_replication=enable_replication,  # Key parameter
        env=cdk.Environment(
            account=config['workload_account'],
            region=config['first_region']
        ),
        synthesizer=synthesizer_factory(config, config['first_region'])
    )
    apply_tags(source_stack, config)
    
    # Set dependency if multi-region
    if enable_replication:
        source_stack.add_dependency(stacks['destination'])
    
    stacks['source'] = source_stack
    return stacks

if __name__ == "__main__":
    config_parser = configparser.ConfigParser()
    config_parser.read(filenames="resource.config")
    branch_name = os.getenv("SRC_BRANCH", "paclive")
    config = config_parser[branch_name]

    app = cdk.App()

    s3_stacks = create_s3_stacks(app, config, get_def_stack_synth)

    source_stack = s3_stacks['source']
    dest_stack = s3_stacks.get('destination')


    # Create infrastructure stacks for each configured region
    deployment_regions = get_deployment_regions(config)
    
    for region in deployment_regions:
        region_stack = f"{region}-"  # Already stripped in get_deployment_regions()

        # Application infra stack
        cdk_stack = cloud_infra(
            app,
            f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}-{region_stack}infra-stack-{config['resource_suffix']}",
            resource_config=config,
            env=cdk.Environment(account=f"{config['workload_account']}",
                                region=region),
            synthesizer=get_def_stack_synth(config, region)
        )
        apply_tags(cdk_stack, config)
        
        # Ensure S3 buckets exist before cloud_infra references them
        if region == config['first_region']:
            cdk_stack.add_dependency(source_stack)
        elif dest_stack and region == config.get('second_region'):
            cdk_stack.add_dependency(dest_stack)


        Aspects.of(app).add(AwsSolutionsChecks())
        NagSuppressions.add_stack_suppressions(cdk_stack, [
            {'id': 'AwsSolutions-IAM4', 'reason': 'AwsSolutions-IAM4'},
            {'id': 'AwsSolutions-IAM5', 'reason': 'AwsSolutions-IAM5'},
            {'id': 'AwsSolutions-ECS2', 'reason': 'AwsSolutions-ECS2'},
            {'id': 'AwsSolutions-ELB2', 'reason': 'AwsSolutions-ELB2'},
            {'id': 'AwsSolutions-SMG4', 'reason': 'AwsSolutions-SMG4'},
            {'id': 'AwsSolutions-S1', 'reason': 'AwsSolutions-S1'},
            {'id': 'AwsSolutions-L1', 'reason': 'AwsSolutions-L1'},
            {'id': 'AwsSolutions-EC26', 'reason': 'SIL AMI already has the EBS volumes encrypted.'},
            {'id': 'AwsSolutions-EC29', 'reason': 'DisableApiTermination is set to true on sil instance.'},
        ])


    app.synth()