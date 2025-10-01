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

def get_def_stack_synth(config, region):
    return cdk.DefaultStackSynthesizer(
        cloud_formation_execution_role=f"arn:aws:iam::{config['workload_account']}:role/{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}dply-role-main-a",
        deploy_role_arn=f"arn:aws:iam::{config['workload_account']}:role/{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}dply-role-main-a",
        file_asset_publishing_role_arn=f"arn:aws:iam::{config['workload_account']}:role/{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}dply-role-main-a",
        image_asset_publishing_role_arn=f"arn:aws:iam::{config['workload_account']}:role/{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}dply-role-main-a",
        lookup_role_arn=f"arn:aws:iam::{config['workload_account']}:role/{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}dply-role-main-a",
        file_assets_bucket_name=f"{config['asset_prefix']}-{config['workload_account']}-{region}-{config['resource_suffix']}",
        # image_assets_repository_name=cdk_custom_configs.get('bootstrap_image_assets_repository_name')
        bootstrap_stack_version_ssm_parameter=f"{config['bootstrap_stack_version']}"
    )

if __name__ == "__main__":
    # Reading Application infra resource varibales using git branch name
    config_parser = configparser.ConfigParser()
    config_parser.read(filenames="resource.config")
    branch_name = os.getenv("SRC_BRANCH", "dev")
    config = config_parser[branch_name]

    # Initializing CDK app
    app = cdk.App()

    for region in config['deployment_regions'].split(","):
        region_stack = f"{region}-" if len(config['deployment_regions'].split(",")) > 1 else ""

        # Application infra stack for resources required for application deployment
        cdk_stack = cloud_infra(
            app,
            f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}-{region_stack}infra-stack-{config['resource_suffix']}",
            resource_config=config,
            env=cdk.Environment(account=f"{config['workload_account']}",
                                region=region),
            synthesizer=get_def_stack_synth(config, region)
        )

        # Add a tag to all constructs in the stack
        Tags.of(cdk_stack).add("sw:application", f"{config['app_name']}")
        Tags.of(cdk_stack).add("sw:product", f"{config['service_name']}")
        Tags.of(cdk_stack).add("sw:environment", f"{config['app_env']}")
        Tags.of(cdk_stack).add("sw:cost_center", f"{config['cost_center']}")

        # Inspect app with cdk-nag before synth
        Aspects.of(app).add(AwsSolutionsChecks())
        NagSuppressions.add_stack_suppressions(cdk_stack, [
            {'id': 'AwsSolutions-IAM4', 'reason': 'AwsSolutions-IAM4'},
            {'id': 'AwsSolutions-IAM5', 'reason': 'AwsSolutions-IAM5'},
            {'id': 'AwsSolutions-ECS2', 'reason': 'AwsSolutions-ECS2'},
            {'id': 'AwsSolutions-ELB2', 'reason': 'AwsSolutions-ELB2'},
            {'id': 'AwsSolutions-SMG4', 'reason': 'AwsSolutions-SMG4'},
            {'id': 'AwsSolutions-S1', 'reason': 'AwsSolutions-S1'},
            {'id': 'AwsSolutions-S1', 'reason': 'AwsSolutions-S1'},
            {'id': 'AwsSolutions-L1', 'reason': 'AwsSolutions-L1'},
        ])

    # Synthesize and produce CloudFormation template
    app.synth()
