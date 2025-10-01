from constructs import Construct

from  stack.jumphost  import MsgDltJumpHost

from aws_cdk import (
    Duration,
    RemovalPolicy,
    Stack,
    aws_s3 as s3,
    aws_iam as iam,
    aws_lambda as _lambda,
    aws_events as events,
    aws_events_targets as targets,
    aws_ecr as ecr,
    aws_ec2 as ec2,
    aws_certificatemanager as cert,
    aws_logs as logs,
    aws_ecs as ecs,
    aws_elasticloadbalancingv2 as elbv2,
    aws_route53 as route53,
    aws_cloudwatch as cloudwatch,
    aws_sns as sns,
    aws_cloudwatch_actions as cloudwatch_actions,
    aws_secretsmanager as secretsmanager,
    SecretValue as secretValue,
    aws_s3_notifications as s3n,
    Names,
    SecretValue,
    aws_ssm as ssm,
    custom_resources as cr,
)
import base64


class cloud_infra(Stack):

    def create_ssm_document_role(self, config, cluster_name, service_name) -> iam.Role:
        # ------------------------------------------------------------------
        # IAM Role for Automation execution (trusts SSM + specific source account)
        # ------------------------------------------------------------------
        combined_principals = iam.CompositePrincipal(iam.ServicePrincipal("ssm.amazonaws.com").with_conditions({
            "StringEquals": {
                "aws:SourceAccount": [ config['monitoring_command_control_account'], config['workload_account'] ]
            },
            "ArnLike": {
                "aws:SourceArn": f"arn:aws:ssm:*:{config['monitoring_command_control_account']}:automation-execution/*"
            }
        }),
            iam.AccountPrincipal(config["monitoring_command_control_account"]).with_conditions({
                "ArnLike": {
                    "aws:PrincipalARN": f"arn:aws:iam::{config['monitoring_command_control_account']}:role/aws-reserved/sso.amazonaws.com/eu-central-1/AWSReservedSSO_sw-nonprod-moncc-cmc-fin-ops*"
                },
                "StringEquals": {
                    "aws:PrincipalOrgID": config['main_lz_org_id']
                }
            })
        )
        document_role = iam.Role(
            self,
            f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}-ssm-{self.region}-role-{config['resource_suffix']}",
            assumed_by=combined_principals,
            role_name=f"{config['resource_prefix']}-{config['service_name']}-{self.region}-systems-manager-automation-execution-role",
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AmazonSSMAutomationRole")
            ]
        )

        # Allow ECS service restart
        document_role.add_to_policy(
            iam.PolicyStatement(
                actions=["ecs:UpdateService"],
                resources=[
                    f"arn:aws:ecs:{self.region}:{config['workload_account']}:service/{cluster_name}/{service_name}"
                ]
            )
        )

        document_role.add_to_policy(
            iam.PolicyStatement(
                actions=["ecs:DescribeTasks", "ecs:ListTasks"],
                resources=["*"]
            )
        )

        return document_role

    def create_ecs_ssm_ecs_restrat_documentation(self, config, cluster_name, service_name, role_arn):
        # ------------------------------------------------------------------
        # SSM Automation Document content
        # ------------------------------------------------------------------
        role_name = role_arn.split('/')[-1]
        document_content = {
            "schemaVersion": "0.3",
            "description": f"Restart GPI API over Internet service - container restart. 1. Select Multi Account 2. Target Account : {config['workload_account']}. 3. Target region : {self.region} 3. Role : {role_name}",
            "assumeRole": "",
            "mainSteps": [
                {
                    "name": "RestartService",
                    "action": "aws:executeAwsApi",
                    "onFailure": "Abort",
                    "inputs": {
                        "Service": "ecs",
                        "Api": "UpdateService",
                        "cluster": cluster_name,
                        "service": service_name,
                        "forceNewDeployment": True
                    }
                }
            ]
        }

        # ------------------------------------------------------------------
        # Create SSM Automation Document
        # ------------------------------------------------------------------
        ssm_document = ssm.CfnDocument(
            self,
            f"{config['resource_prefix']}-{config['ssm_service_area']}-{config['service_name']}-{config['app_env']}-{config['app_name']}-ecs-service-restart-{self.region}",
            content=document_content,
            document_type="Automation",
            update_method="NewVersion",
            name=f"{config['resource_prefix']}-{config['ssm_service_area']}-{config['service_name']}-{config['app_env']}-{config['app_name']}-ecs-service-restart-{self.region}"
        )

        # ------------------------------------------------------------------
        # Share Document with another AWS account
        # ------------------------------------------------------------------

        cr_policy = cr.AwsCustomResourcePolicy.from_statements([
            iam.PolicyStatement(
                actions=["ssm:ModifyDocumentPermission"],
                resources=[
                    f"arn:aws:ssm:{self.region}:{self.account}:document/*"]
            )
        ])

        # Create a custom resource to set document permissions
        custom_resource = cr.AwsCustomResource(
            self, "CustomResource-restart-" + config['service_name'],
            on_create=cr.AwsSdkCall(
                service="SSM",
                action="modifyDocumentPermission",
                parameters={
                    "Name": ssm_document.ref,
                    "PermissionType": "Share",
                    "AccountIdsToAdd": [config['monitoring_command_control_account']]
                },
                physical_resource_id=cr.PhysicalResourceId.of(ssm_document.ref)
            ),
            on_update=cr.AwsSdkCall(
                service="SSM",
                action="modifyDocumentPermission",
                parameters={
                    "Name": ssm_document.ref,
                    "PermissionType": "Share",
                    "AccountIdsToAdd": [config['monitoring_command_control_account']]
                },
                physical_resource_id=cr.PhysicalResourceId.of(ssm_document.ref)
            ),
            on_delete=cr.AwsSdkCall(
                service="SSM",
                action="modifyDocumentPermission",
                parameters={
                    "Name": ssm_document.ref,
                    "PermissionType": "Share",
                    "AccountIdsToRemove": [config['monitoring_command_control_account']]
                },
                physical_resource_id=cr.PhysicalResourceId.of(ssm_document.ref)
            ),
            policy=cr_policy
        )
        custom_resource.node.add_dependency(ssm_document)

        return

    def create_ecs_ssm_ecs_status_documentation(self, config, cluster_name, service_name, role_arn):
        # ------------------------------------------------------------------
        # SSM Automation Document content
        # ------------------------------------------------------------------
        role_name = role_arn.split('/')[-1]

        document_content = {
            "schemaVersion": "0.3",
            "description": f"""
                This Automation document checks the status of all ECS Fargate tasks
                running under a given ECS Service in a specified AWS Account and Region.
                1. Select Multi Account 2. Target Account : {config['workload_account']}. 3. Target region : {self.region} 3. Role : {role_name}
                
                Use case:
                    - When ECS workloads are owned by a central account, but need to be monitored
                    or queried by operators in remote accounts.
                    - This workflow allows remote operators to check task health/status without
                    direct ECS access, by assuming a cross-account IAM role.
                
                Outputs:
                    - OwningAccount
                    - Region
                    - Cluster
                    - Service
                    - Task ARNs
                    - TaskStatuses (RUNNING, PENDING, STOPPED)
                    - DesiredStatuses
                    - ContainerStatuses
                    - StoppedReasons (if applicable)

            """,
            "assumeRole": "",
            "mainSteps": [
                {
                    "name": "ListTasks",
                    "action": "aws:executeAwsApi",
                    "description": "Step 1: List ECS Tasks list.",
                    "onFailure": "Abort",
                    "inputs": {
                        "Service": "ecs",
                        "Api": "ListTasks",
                        "cluster": cluster_name
                    },
                    "outputs": [
                        {
                            "Name": "TaskArns",
                            "Selector": "$.taskArns",
                            "Type": "StringList"
                        }
                    ]
                },
                {
                    "name": "DescribeTasks",
                    "action": "aws:executeAwsApi",
                    "description": "Step 2: Describe the ECS tasks to get detailed status information.",
                    "inputs": {
                        "Service": "ecs",
                        "Api": "DescribeTasks",
                        "cluster": cluster_name,
                        "tasks": "{{ ListTasks.TaskArns }}"
                    },
                    "outputs": [
                        {
                            "Name": "Tasks",
                            "Selector": "$.tasks",
                            "Type": "MapList"
                        }
                    ]
                },
                {
                    "name": "ShowStatus",
                    "action": "aws:executeScript",
                    "description": "Step 3: Format and output ECS task status results.",
                    "inputs": {
                        "Runtime": "python3.11",
                        "Handler": "script_handler",
                        "InputPayload": {
                            "Message": "{{ DescribeTasks.Tasks }}"
                        },
                        "Script": """
def script_handler(events, context):
    print(events["Message"])
    return {
        "TaskDetails": events["Message"]
    }
                        """
                    },
                    "outputs": [
                        {
                            "Name": "TaskDetails",
                            "Selector": "$.TaskDetails",
                            "Type": "MapList"
                        }
                    ]
                }
            ]
        }

        # ------------------------------------------------------------------
        # Create SSM Automation Document
        # ------------------------------------------------------------------
        ssm_document = ssm.CfnDocument(
            self,
            f"{config['resource_prefix']}-{config['ssm_service_area']}-{config['service_name']}-{config['app_env']}-{config['app_name']}-ecs-task-status-{self.region}",
            content=document_content,
            document_type="Automation",
            update_method="NewVersion",
            name=f"{config['resource_prefix']}-{config['ssm_service_area']}-{config['service_name']}-{config['app_env']}-{config['app_name']}-ecs-task-status-{self.region}"
        )

        # ------------------------------------------------------------------
        # Share Document with another AWS account
        # ------------------------------------------------------------------

        cr_policy = cr.AwsCustomResourcePolicy.from_statements([
            iam.PolicyStatement(
                actions=["ssm:ModifyDocumentPermission"],
                resources=[
                    f"arn:aws:ssm:{self.region}:{self.account}:document/*"]
            )
        ])

        # Create a custom resource to set document permissions
        custom_resource = cr.AwsCustomResource(
            self, "CustomResource-status-" + config['service_name'],
            on_create=cr.AwsSdkCall(
                service="SSM",
                action="modifyDocumentPermission",
                parameters={
                    "Name": ssm_document.ref,
                    "PermissionType": "Share",
                    "AccountIdsToAdd": [config['monitoring_command_control_account']]
                },
                physical_resource_id=cr.PhysicalResourceId.of(ssm_document.ref)
            ),
            on_update=cr.AwsSdkCall(
                service="SSM",
                action="modifyDocumentPermission",
                parameters={
                    "Name": ssm_document.ref,
                    "PermissionType": "Share",
                    "AccountIdsToAdd": [config['monitoring_command_control_account']]
                },
                physical_resource_id=cr.PhysicalResourceId.of(ssm_document.ref)
            ),
            on_delete=cr.AwsSdkCall(
                service="SSM",
                action="modifyDocumentPermission",
                parameters={
                    "Name": ssm_document.ref,
                    "PermissionType": "Share",
                    "AccountIdsToRemove": [config['monitoring_command_control_account']]
                },
                physical_resource_id=cr.PhysicalResourceId.of(ssm_document.ref)
            ),
            policy=cr_policy
        )
        custom_resource.node.add_dependency(ssm_document)

        return


        # Create task execution role for ECS service task execution to have permission to pull container image
    def create_task_execution_role(self, config, repo_name, prefix) -> iam.Role:
        ecs_task_exec_role = iam.Role(
            self,
            id=f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}{prefix}-ecs-task-exec-{self.region}-role-{config['resource_suffix']}",
            assumed_by=iam.ServicePrincipal('ecs-tasks.amazonaws.com'),
            role_name=f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}{prefix}-ecs-task-exec-{self.region}-role-{config['resource_suffix']}"
        )

        ecs_task_exec_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    'ecr:BatchCheckLayerAvailability',
                    'ecr:BatchGetImage',
                    'ecr:GetDownloadUrlForLayer'
                ],
                resources=[
                    f"arn:aws:ecr:*:{config['deployment_sdlc_account']}:repository/{repo_name}"
                ]
            )
        )

        ecs_task_exec_role.add_to_policy(
            iam.PolicyStatement(effect=iam.Effect.ALLOW,
                                actions=['ecr:GetAuthorizationToken'],
                                resources=["*"]
                                )
        )

        ecs_task_exec_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["logs:CreateLogStream", "logs:PutLogEvents"],
                resources=["arn:aws:logs:*:*:log-group:*:*"]
            )
        )

        ecs_task_exec_role.add_to_policy(
            iam.PolicyStatement(effect=iam.Effect.ALLOW,
                                actions=["secretsmanager:GetSecretValue",
                                         "secretsmanager:DescribeSecret",
                                         "secretsmanager:ListSecrets"
                                         ],
                                resources=[
                                    f"arn:aws:secretsmanager:{self.region}:{config['workload_account']}:secret:*"])
        )

        return ecs_task_exec_role

    # Create task execution role for ECS service task
    def create_task_role(self, config) -> iam.Role:
        ecs_task_role = iam.Role(
            self,
            f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}-task-{self.region}-role-{config['resource_suffix']}",
            assumed_by=iam.ServicePrincipal('ecs-tasks.amazonaws.com'),
            role_name=f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}-task-{self.region}-role-{config['resource_suffix']}"
        )

        ecs_task_role.add_to_policy(
            iam.PolicyStatement(effect=iam.Effect.ALLOW,
                                actions=['cloudwatch:*'],
                                resources=["*"])
        )

        ecs_task_role.add_to_policy(
            iam.PolicyStatement(effect=iam.Effect.ALLOW,
                                actions=["secretsmanager:GetSecretValue",
                                         "secretsmanager:DescribeSecret",
                                         "secretsmanager:ListSecrets"
                                         ],
                                resources=[
                                    f"arn:aws:secretsmanager:{self.region}:{config['workload_account']}:secret:*"])
        )

        return ecs_task_role

    def lookup_vpc(self, config):
        # vpc lookup from account
        vpc = ec2.Vpc.from_lookup(
            self,
            f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}-vpc-{config['resource_suffix']}",
            vpc_id=f"{config['vpc_id_' + self.region]}"
        )

        return vpc

    def lookup_subnet(self, subnet_1, subnet_2):
        subnet = ec2.SubnetSelection(
            # one_per_az=True,
            subnet_filters=[
                ec2.SubnetFilter.by_ids([
                    f"{subnet_1}", f"{subnet_2}"
                ])
            ]
        )

        return subnet

    def get_hosted_zone(self, config):
        hosted_zone = route53.HostedZone.from_hosted_zone_id(
            self,
            f"{config['service_name']}.{config['app_env']}.{config['cloud_hosted_domain']}",
            f"{config['hosted_zone_id']}"
        )

        return hosted_zone

    def create_certificate(self, config, name, hosted_zone):
        certificate = cert.Certificate(
            self,
            id=f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}-{name}-{config['resource_suffix']}",
            domain_name=f"{config['service_name']}.{config['app_env']}.{config['cloud_hosted_domain']}",
            certificate_name=f"{config['certificate_name']}",
            validation=cert.CertificateValidation.from_dns(hosted_zone)
        )

        return certificate

    def create_log_group(self, config, name):
        log_group = logs.LogGroup(
            self,
            id=f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}-{name}-{config['resource_suffix']}",
            log_group_name=f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}-{name}-{config['resource_suffix']}",
            retention=logs.RetentionDays.ONE_MONTH,
            removal_policy=RemovalPolicy.DESTROY,
        )

        return log_group

    def create_fargate_task(self, config, ecs_task_role, ecs_task_execution_role, repo_name, repo_version, prefix,
                            log_group, secret, password_secret, client_secret):

        volume_name = f"{config['service_name']}{prefix}-tmp-volume"

        # Container image reference from ECR repository
        image_repository = ecr.Repository.from_repository_arn(
            self,
            id=f"ecs-repository{prefix}",
            repository_arn=f"arn:aws:ecr:{self.region}:{config['deployment_sdlc_account']}:repository/{repo_name}"
        )

        # create task definition, commented out until needed, letting AWS auto configure
        task_definition = ecs.FargateTaskDefinition(
            self,
            id=f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}{prefix}-ecs-task-definition-{config['resource_suffix']}",
            cpu=int(f"{config['container_cpu']}"),
            memory_limit_mib=int(f"{config['container_mem']}"),
            task_role=ecs_task_role,
            volumes=[ecs.Volume(name=volume_name)],
            execution_role=ecs_task_execution_role)

        container_definition = ecs.ContainerDefinition(
            self,
            id=f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}{prefix}-ecs-container-definition-{config['resource_suffix']}",
            image=ecs.ContainerImage.from_ecr_repository(image_repository, f"{repo_version}"),
            task_definition=task_definition,
            cpu=int(f"{config['container_cpu']}"),
            environment={
                "AWS_STS_REGIONAL_ENDPOINTS": self.region,
                "APP_ENV": f"{config['app_env']}",
                "AWS_STS_ZONE_ENDPOINTS": f"{config['hosted_zone_id']}",
                "APP_LIVE_OR_TNT": f"{config['app_live_or_pilot']}",
                "external.apigeejwt.audience": f"{config['audience_url']}",
                "AWS_ENV_ZONE": f"{config['aws_env_zone']}",
                "account_id": f"{config['workload_account']}",
                "account_name": f"main-{config['service_name']}-{config['app_env']}-aws-account",
                "productId": f"{config['productId']}",
                "healthcheck.uetr": f"{config['healthcheck.uetr']}",
                "userContext": f"{config['userContext']}",
                "client_id": f"{config['client_id']}",
                "scope": f"{config['scope']}",
                "audience_url": f"{config['audience_url']}",
                "token_uri": f"{config['token_uri']}",
                "apigee_url": f"{config['apigee_url']}"
            },
            secrets={
                "base64value": ecs.Secret.from_secrets_manager(secret),
                "keystore.password": ecs.Secret.from_secrets_manager(password_secret),
                "client_secret":  ecs.Secret.from_secrets_manager(client_secret)
            },
            readonly_root_filesystem=True,
            health_check=ecs.HealthCheck(
                command=["CMD-SHELL", f"{config['health_check_command']}"],
                interval=Duration.seconds(30),
                retries=3,
                start_period=Duration.minutes(1),
                timeout=Duration.seconds(10)
            ),
            logging=ecs.LogDriver.aws_logs(
                stream_prefix=f"{config['service_name']}{prefix}-app",
                log_group=log_group
            ),
            memory_limit_mib=int(f"{config['container_mem']}"),
            memory_reservation_mib=int(f"{config['container_mem']}"),
            port_mappings=[
                ecs.PortMapping(
                    container_port=int(f"{config['container_port']}"),
                    protocol=ecs.Protocol.TCP)
            ]
        )

        container_definition.add_mount_points(
            ecs.MountPoint(container_path="/tmp",
                           read_only=False,
                           source_volume=volume_name))

        return task_definition

    def create_ecs_security_group(self, config, vpc, prefix):

        # ECS security group
        ecs_sg = ec2.SecurityGroup(
            self,
            id=f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}{prefix}-ecs-sg-{config['resource_suffix']}",
            security_group_name=f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}{prefix}-ecs-sg-{config['resource_suffix']}",
            description="Allow the communication from ECS to NLB.",
            allow_all_outbound=True,
            # if this is set to `false` then no egress rule will be automatically created
            vpc=vpc
        )

        # Security group for NLB and ECS
        ecs_sg.add_ingress_rule(
            ec2.Peer.ipv4(vpc.vpc_cidr_block),
            ec2.Port.tcp(int(f"{config['container_port']}"))
        )

        return ecs_sg

    # Load balancer security group
    def create_lb_security_group(self, config, vpc, prefix):

        # ECS security group
        lb_sg = ec2.SecurityGroup(
            self,
            id=f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}{prefix}-lb-sg-{config['resource_suffix']}",
            security_group_name=f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}{prefix}-lb-sg-{config['resource_suffix']}",
            description="Allow the communication from NLB to ECS and VPCE.",
            allow_all_outbound=True,
            # if this is set to `false` then no egress rule will be automatically created
            vpc=vpc
        )

        lb_sg.add_ingress_rule(
            ec2.Peer.ipv4(vpc.vpc_cidr_block),
            ec2.Port.tcp(443)
        )

        for ip in config['onprem_ips_' + self.region].split(","):
            lb_sg.add_ingress_rule(
                ec2.Peer.ipv4(ip),
                ec2.Port.tcp(443)
            )

        return lb_sg

    # create ECS Farget cluster
    def create_ecs_cluster(self, config, vpc):

        cluster = ecs.Cluster(
            self,
            id=f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-ecs-cluster-{config['resource_suffix']}",
            cluster_name=f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-ecs-cluster-{config['resource_suffix']}",
            vpc=vpc,
            container_insights=True,
        )

        return cluster

    def create_ecs_fargate_service(self, config, cluster, task_definition, vpc, prefix):

        sg = self.create_ecs_security_group(config=config, vpc=vpc, prefix=prefix)

        service = ecs.FargateService(
            self,
            id=f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}{prefix}-ecs-service-{config['resource_suffix']}",
            service_name=f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}{prefix}-ecs-service-{config['resource_suffix']}",
            cluster=cluster,
            task_definition=task_definition,
            assign_public_ip=False,
            desired_count=int(config['desired_count']),
            propagate_tags=ecs.PropagatedTagSource.TASK_DEFINITION,
            security_groups=[sg],
            vpc_subnets=self.lookup_subnet(subnet_1=f"{config['workload_subnet_1_' + self.region]}",
                                           subnet_2=f"{config['workload_subnet_2_' + self.region]}"),
            circuit_breaker=ecs.DeploymentCircuitBreaker(rollback=True)
        )

        return service

    def create_load_balancer(self, config, vpc, fargate_service, hosted_zone, prefix):
        # Create NLB
        nlb = elbv2.NetworkLoadBalancer(
            self,
            id=f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}{prefix}-nlb-{config['resource_suffix']}",
            vpc=vpc,
            vpc_subnets=self.lookup_subnet(subnet_1=f"{config['lb_subnet_1_' + self.region]}",
                                           subnet_2=f"{config['lb_subnet_2_' + self.region]}"),
            internet_facing=False,
            load_balancer_name=f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}{prefix}-nlb-{config['resource_suffix']}",
            security_groups=[self.create_lb_security_group(config=config, vpc=vpc, prefix=prefix)]
        )

        # cfn_nlb = nlb.node.default_child
        # cfn_nlb.add_override("Properties.SubnetMappings", [
        #     {
        #         "SubnetId": config['lb_subnet_1'],
        #         "PrivateIPv4Address": config['private_ip_1']
        #     },
        #     {
        #         "SubnetId": config['lb_subnet_2'],
        #         "PrivateIPv4Address": config['private_ip_2']
        #    }
        # ])
        # (Optional) Clear the default Subnets property to avoid conflict
        # cfn_nlb.add_override("Properties.Subnets", None)

        # Create target group for service
        target_group = elbv2.NetworkTargetGroup(
            self,
            id=f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}{prefix}-nlb-tg-{config['resource_suffix']}",
            port=int(f"{config['container_port']}"),
            protocol=elbv2.Protocol.TLS,
            targets=[fargate_service],
            vpc=vpc
        )

        nlb.add_listener(
            id=f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}{prefix}-nlb-listener-{config['resource_suffix']}",
            port=443,
            default_target_groups=[target_group],
            certificates=[self.create_certificate(config=config, name=f"lb-certs{prefix}", hosted_zone=hosted_zone)]
        )

        return nlb, target_group

    # Cloudwatch Alarm for NLB
    def create_nlb_tg_cloudwatch_alarm(self, config, target_group, sns_topic, nlb):
        tg_name = Names.unique_id(target_group) + "-nlb-target-group"
        nlb_name = nlb.load_balancer_name
        # Alarm: Unhealthy hosts threshold 1
        unhealthy_hosts_alarm = cloudwatch.Alarm(
            self,
            f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}-unhealthy-hosts-alarm-{config['resource_suffix']}",
            metric=target_group.metric_un_healthy_host_count(),
            threshold=int(config.get("unhealthy_hosts_threshold", 1)),
            evaluation_periods=int(config['nlb_evaluation_periods']),
            datapoints_to_alarm=int(config['nlb_datapoints_to_alarm']),
            alarm_description=f"Target Group [{tg_name}] has more than {config.get('unhealthy_hosts_threshold', 1)} unhealthy hosts.",
            alarm_name=f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}-unhealthy-hosts-alarm-{config['resource_suffix']}",
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING)

        unhealthy_hosts_alarm.add_alarm_action(cloudwatch_actions.SnsAction(sns_topic))

        # Alarm: Healthy hosts threshold 2
        if "healthy_hosts_threshold" in config:
            healthy_hosts_alarm = cloudwatch.Alarm(
                self,
                f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}-healthy-hosts-alarm-{config['resource_suffix']}",
                metric=target_group.metric_healthy_host_count(),
                threshold=int(config["healthy_hosts_threshold"]),
                comparison_operator=cloudwatch.ComparisonOperator.LESS_THAN_THRESHOLD,
                evaluation_periods=int(config['nlb_evaluation_periods']),
                datapoints_to_alarm=int(config['nlb_datapoints_to_alarm']),
                alarm_description=f"Target Group [{tg_name}] has fewer than {config['healthy_hosts_threshold']} healthy hosts.",
                alarm_name=f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}-healthy-hosts-alarm-{config['resource_suffix']}",
                treat_missing_data=cloudwatch.TreatMissingData.BREACHING)

            healthy_hosts_alarm.add_alarm_action(cloudwatch_actions.SnsAction(sns_topic))

        # Alarm: ActiveFlowCount

        active_flow_metric = cloudwatch.Metric(
            namespace="AWS/NetworkELB",
            metric_name="ActiveFlowCount",
            dimensions_map={
                "TargetGroup": tg_name,
                "LoadBalancer": nlb_name
            },
            statistic="Average",
            period=Duration.minutes(1)
        )

        active_flow_alarm = cloudwatch.Alarm(
            self,
            f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}-active-flow-alarm-{config['resource_suffix']}",
            metric=active_flow_metric,
            threshold=int(config.get("active_flow_threshold", 200)),
            evaluation_periods=int(config['nlb_evaluation_periods']),
            datapoints_to_alarm=int(config['nlb_datapoints_to_alarm']),
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
            alarm_description=f"Target Group [{tg_name}] ActiveFlowCount exceeds {config.get('active_flow_threshold', 100)}",
            alarm_name=f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}-active-flow-alarm-{config['resource_suffix']}",
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING
        )
        active_flow_alarm.add_alarm_action(cloudwatch_actions.SnsAction(sns_topic))

    # Endpoint service for private link
    def create_vpc_endpoint_service(self, config, nlb, prefix):

        endpoint_service = ec2.VpcEndpointService(
            self,
            id=f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}{prefix}-vpce-service-{config['resource_suffix']}",
            vpc_endpoint_service_load_balancers=[nlb],
            acceptance_required=False,
            allowed_principals=[iam.ArnPrincipal(
                f"arn:aws:iam::{config['workload_idmz_account']}:role/{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-idmzdply-role-main-a")],
        )

        return endpoint_service

    def create_oasis_log_integrations(self, config, log_group):
        logs.CfnSubscriptionFilter(
            self,
            id=f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}-event-subfilter-{config['resource_suffix']}",
            filter_name=f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}-event-subfilter-{config['resource_suffix']}",
            filter_pattern="{ $.event.kind = Alert }",
            log_group_name=log_group.log_group_name,
            destination_arn=f"arn:aws:lambda:{self.region}:{config['workload_account']}:function:{config['resource_prefix']}-monitor-lambda-sns-forwarder-{config['monitoring_env']}-{self.region}-{config['resource_suffix']}"
        )

        logs.CfnSubscriptionFilter(
            self,
            id=f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}-oasis-subfilter-{config['resource_suffix']}",
            filter_name=f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}-oasis-subfilter-{config['resource_suffix']}",
            filter_pattern="common cloud account",
            log_group_name=log_group.log_group_name,
            destination_arn=f"arn:aws:logs:{self.region}:{config['monitoring_tools_account']}:destination:{config['resource_prefix']}-oasis-{config['service_name']}-{config['app_name']}-{config['monitoring_env']}-cwdestination-{config['resource_suffix']}"
        )

    def create_ecs_cloudwatch_alarms(self, config, fargate_service, sns_topic):
        # ECS CPU and Memory monitoring
        # Parse name from object ID, format name like acp-ecs-service
        service_name = Names.unique_id(fargate_service).partition("aws")[-1].partition("ecs")[0] + "-ecs-service"

        # Create a CloudWatch alarm for CPU Utilization
        cpu_utilization_alarm = cloudwatch.Alarm(self,
                                                 f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}-cpu-utilization-alarm-{config['resource_suffix']}",
                                                 metric=fargate_service.metric_cpu_utilization(),
                                                 threshold=int(config['cpu_utilization_threshold']),
                                                 evaluation_periods=int(config['evaluation_periods']),
                                                 datapoints_to_alarm=int(config['datapoints_to_alarm']),
                                                 alarm_description=f"ECS service [{config['service_name']}] CPU utilization exceeds threshold value {config['cpu_utilization_threshold']}%",
                                                 alarm_name=f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}-cpu-utilization-alarm-{config['resource_suffix']}",
                                                 treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING)

        # Subscribe the SNS topic to the CPU alarm
        cpu_utilization_alarm.add_alarm_action(cloudwatch_actions.SnsAction(sns_topic))

        # Create a CloudWatch alarm for Memory Utilization
        memory_utilization_alarm = cloudwatch.Alarm(self,
                                                    f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}-memory-utilization-alarm-{config['resource_suffix']}",
                                                    metric=fargate_service.metric_memory_utilization(),
                                                    threshold=int(config['memory_utilization_threshold']),
                                                    evaluation_periods=int(config['evaluation_periods']),
                                                    datapoints_to_alarm=int(config['datapoints_to_alarm']),
                                                    alarm_description=f"ECS service [{config['service_name']}] memory utilization exceeds threshold value {config['memory_utilization_threshold']}%",
                                                    alarm_name=f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}-memory-utilization-alarm-{config['resource_suffix']}",
                                                    treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING)

        # Subscribe the SNS topic to the Memory alarm
        memory_utilization_alarm.add_alarm_action(cloudwatch_actions.SnsAction(sns_topic))

    def get_sns_topic_ref(self, config):
        topic_name = config['sns_topic'].replace("zonename", self.region)
        sns_topic = sns.Topic.from_topic_arn(
            self,
            f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}-sns-topic-{config['resource_suffix']}",
            topic_arn=f"arn:aws:sns:{self.region}:{config['workload_account']}:{topic_name}"
        )

        return sns_topic

    def create_secret(self, config, usage_type=""):
        # Base64 encode the string "changeme"
        plaintext = "changeme"
        encoded = base64.b64encode(plaintext.encode("utf-8")).decode("utf-8")

        # Wrap it as a SecretValue
        secret_value = SecretValue.unsafe_plain_text(encoded)

        # Create the secret in Secrets Manager
        jks_secret = secretsmanager.Secret(
            self,
            id=f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}{usage_type}-secret-{config['resource_suffix']}",
            secret_name=f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}{usage_type}-secret-{config['resource_suffix']}",
            description="Secret Manager resource",
            secret_string_value=secret_value
        )

        return jks_secret

    def setup_jks_integration(self, config, jks_secret, password_secret, client_secret):
        # 1. S3 bucket for uploading JKS files
        jks_bucket = s3.Bucket(
            self,
            f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}-secret-s3-{self.region}-{config['resource_suffix']}",
            bucket_name=f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}-secret-s3-{self.region}-{config['resource_suffix']}",
            encryption=s3.BucketEncryption.S3_MANAGED,
            minimum_tls_version=1.2,
            object_ownership=s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
            object_lock_enabled=False,
            versioned=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            removal_policy=RemovalPolicy.DESTROY,
            enforce_ssl=True,
            lifecycle_rules=[s3.LifecycleRule(
                enabled=True,
                id=f"secret-s3-lifecycle",
                noncurrent_version_expiration=Duration.days(180),
                noncurrent_versions_to_retain=5
            )
            ]
        )

        # 2. Lambda function to process uploaded JKS files

        jks_lambda_fn_role = iam.Role(
            self,
            f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}-secret-lambda-role-{self.region}-{config['resource_suffix']}",
            role_name=f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}-secret-lambda-role-{self.region}-{config['resource_suffix']}",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com")
        )

        jks_lambda_fn_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole")
        )

        # Permissions to read from S3 bucket
        jks_lambda_fn_role.add_to_policy(
            iam.PolicyStatement(
                actions=["s3:GetObject"],
                resources=[f"{jks_bucket.bucket_arn}/*"]
            )
        )

        jks_lambda_fn_role.add_to_policy(
            iam.PolicyStatement(
                actions=["secretsmanager:PutSecretValue"],
                resources=[jks_secret.secret_arn, password_secret.secret_arn, client_secret.secret_arn]
            )
        )

        _lambda_name = f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}-secret-lambda-{config['resource_suffix']}"
        jks_lambda_fn = _lambda.Function(
            self,
            _lambda_name,
            function_name=_lambda_name,
            runtime=_lambda.Runtime.PYTHON_3_13,
            handler="jks_integration.handler",
            code=_lambda.Code.from_asset("lambda"),
            environment={
                "SECRET_NAME": jks_secret.secret_name,
                "PASSWORD_SECRET_ARN": password_secret.secret_arn,
                "CLIENT_SECRET_ARN": client_secret.secret_arn
            },
            log_group=logs.LogGroup(self,
                                    f"{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}-secret-lambda-lg-{config['resource_suffix']}",
                                    log_group_name=f"/aws/logs/{_lambda_name}",
                                    retention=logs.RetentionDays.ONE_MONTH,
                                    removal_policy=RemovalPolicy.DESTROY,
                                    ),
            role=jks_lambda_fn_role
        )

        # Permissions
        # jks_bucket.grant_read(jks_lambda_fn)
        # jks_secret.grant_write(jks_lambda_fn)

        _jks_uploader_principals = [
            f"arn:aws:sts::{config['workload_account']}:assumed-role/AWSReservedSSO_{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-poweruser_*"
        ]
        if config['app_env'] in ['pilot', 'live']:
            _jks_uploader_principals.append(f"arn:aws:iam::{config['workload_account']}:user/ckwilliams")

        jks_bucket.add_to_resource_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                principals=[jks_lambda_fn_role],
                actions=["s3:GetObject"],
                resources=[f"{jks_bucket.bucket_arn}/*.jks", f"{jks_bucket.bucket_arn}/*.password"]
            )
        )

        ### Revisit this policy -
        # jks_bucket.add_to_resource_policy(
        #     iam.PolicyStatement(
        #         effect=iam.Effect.ALLOW,
        #         principals=[iam.AnyPrincipal()],
        #         actions=["s3:PutObject"],
        #         resources=[f"{jks_bucket.bucket_arn}/*.jks", f"{jks_bucket.bucket_arn}/*.password"],
        #         conditions={
        #             "StringLike": {
        #                 "aws:PrincipalArn": _jks_uploader_principals
        #             }
        #         }
        #     )
        # )

        # jks_bucket.add_to_resource_policy(
        #     iam.PolicyStatement(
        #         effect=iam.Effect.DENY,
        #         principals=[iam.AnyPrincipal()],
        #         actions=["s3:PutObject"],
        #         resources=[f"{jks_bucket.bucket_arn}/*.jks", f"{jks_bucket.bucket_arn}/*.password"],
        #         conditions={
        #             "StringNotLike": {
        #                 "aws:PrincipalArn": _jks_uploader_principals
        #             }
        #         }
        #     )
        # )

        jks_bucket.add_to_resource_policy(
            iam.PolicyStatement(
                effect=iam.Effect.DENY,
                principals=[iam.AnyPrincipal()],
                actions=["s3:GetObject"],
                resources=[f"{jks_bucket.bucket_arn}/*.jks", f"{jks_bucket.bucket_arn}/*.password"],
                conditions={
                    "StringNotLike": {
                        "aws:PrincipalArn": [
                            jks_lambda_fn_role.role_arn,
                        ]
                    }
                }
            )
        )

        # S3 event notification for .jks files
        jks_bucket.add_event_notification(
            s3.EventType.OBJECT_CREATED,
            s3n.LambdaDestination(jks_lambda_fn),
            s3.NotificationKeyFilter(suffix=".jks")
        )

        # S3 event notification for .password files
        jks_bucket.add_event_notification(
            s3.EventType.OBJECT_CREATED,
            s3n.LambdaDestination(jks_lambda_fn),
            s3.NotificationKeyFilter(suffix=".password")
        )

    def create_secret_resource_policy(self, config, secret, ecs_task_role, ecs_task_exec_role):
        human_role = f"assumed-role/AWSReservedSSO_{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-poweruser_*" if \
            config['app_env'] in ['dev', 'si', 'pac'] else "user/ckwilliams"

        statements = [
            # PutResourcePolicy for Deployment Role
            iam.PolicyStatement(
                actions=["secretsmanager:PutResourcePolicy", "secretsmanager:DescribeSecret"],
                principals=[iam.AccountRootPrincipal()],
                resources=[secret.secret_arn],
                conditions={"ArnEquals": {
                    "aws:PrincipalArn": f"arn:aws:iam::{config['workload_account']}:role/{config['resource_prefix']}-{config['service_name']}-{config['app_env']}-{config['app_name']}dply-role-main-a"}}
            ),
            # Read access for ECS Task Exec Role
            iam.PolicyStatement(
                actions=["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"],
                principals=[iam.AccountRootPrincipal()],
                resources=[secret.secret_arn],
                conditions={"ArnEquals": {"aws:PrincipalArn": ecs_task_exec_role.role_arn}}
            ),
            # Read access for ECS Task Role
            iam.PolicyStatement(
                actions=["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"],
                principals=[iam.AccountRootPrincipal()],
                resources=[secret.secret_arn],
                conditions={"ArnEquals": {"aws:PrincipalArn": ecs_task_role.role_arn}}
            ),
            # Update access for SSO Role
            iam.PolicyStatement(
                actions=["secretsmanager:UpdateSecret", "secretsmanager:PutSecretValue"],
                principals=[iam.AccountRootPrincipal()],
                resources=[secret.secret_arn],
                conditions={"ArnLike": {"aws:PrincipalArn": f"arn:aws:sts::{config['workload_account']}:{human_role}"}}
            ),
            # Deletion access only for Super Role
            iam.PolicyStatement(
                actions=["secretsmanager:DeleteSecret"],
                principals=[iam.AccountRootPrincipal()],
                resources=[secret.secret_arn],
                conditions={"ArnEquals": {
                    "aws:PrincipalArn": f"arn:aws:iam::{config['workload_account']}:role/AWSControlTowerExecution"}}
            )
        ]

        for statement in statements:
            secret.add_to_resource_policy(statement)

    def __init__(self, scope: Construct, construct_id: str, resource_config, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Get configuration variables from resource file
        config = resource_config

        # vpc lookup from account
        vpc = self.lookup_vpc(config=config)

        # ECS, LB and Endpoint for API backend App
        api_ecs_task_execution_role = self.create_task_execution_role(config=config,
                                                                      repo_name=config['ecr_repo_name'],
                                                                      prefix='')
        ecs_task_role = self.create_task_role(config=config)

        hosted_zone = self.get_hosted_zone(config=config)

        _jump_host = MsgDltJumpHost(
            self,
            Utils.resource_id_helper("jump-host"),
            stack_config=stack_config,
            network=_network,
            efs_fs=_efs
        ).launch_jump_host()


        # create ECS Farget cluster
        cluster = self.create_ecs_cluster(config=config, vpc=vpc)

        # Create Log group for ECS apps
        log_group = self.create_log_group(config=config, name=f"ecs-app-logs")

        # Create secret - for certificate
        secret = self.create_secret(config=config)

        self.create_secret_resource_policy(config=config, secret=secret, ecs_task_role=ecs_task_role,
                                           ecs_task_exec_role=api_ecs_task_execution_role)

        # Create secret - for certificate
        password_secret = self.create_secret(config=config, usage_type="jkspassword")


        self.create_secret_resource_policy(config=config, secret=password_secret, ecs_task_role=ecs_task_role,
                                           ecs_task_exec_role=api_ecs_task_execution_role)

        # Create secret for client id
        client_secret = self.create_secret(config=config, usage_type="clientpassword")

        self.create_secret_resource_policy(config=config, secret=client_secret, ecs_task_role=ecs_task_role,
                                           ecs_task_exec_role=api_ecs_task_execution_role)

        # Create ECS task definition
        task_api_definition = self.create_fargate_task(config=config,
                                                       ecs_task_role=ecs_task_role,
                                                       ecs_task_execution_role=api_ecs_task_execution_role,
                                                       repo_name=config['ecr_repo_name'],
                                                       repo_version=config['image_version'],
                                                       prefix='',
                                                       log_group=log_group,
                                                       secret=secret,
                                                       password_secret=password_secret,
                                                       client_secret=client_secret
                                                       )

        # Create ECS container service to host application
        api_service = self.create_ecs_fargate_service(config=config,
                                                      cluster=cluster,
                                                      task_definition=task_api_definition,
                                                      vpc=vpc,
                                                      prefix=''
                                                      )

        # Create load balancer and target to container service
        api_nlb, target_group = self.create_load_balancer(config=config,
                                                          vpc=vpc,
                                                          fargate_service=api_service,
                                                          hosted_zone=hosted_zone,
                                                          prefix=''
                                                          )

        if config['app_env'] not in ['dev', 'si']:
            api_ep = self.create_vpc_endpoint_service(config=config, nlb=api_nlb, prefix='')

        # Monitoring of ECS cluster
        sns_topic = self.get_sns_topic_ref(config=config)

        self.create_ecs_cloudwatch_alarms(config=config, fargate_service=api_service, sns_topic=sns_topic)

        self.create_oasis_log_integrations(config=config, log_group=log_group)

        self.setup_jks_integration(config=config, jks_secret=secret, password_secret=password_secret, client_secret=client_secret)

        self.create_nlb_tg_cloudwatch_alarm(config=config, target_group=target_group, sns_topic=sns_topic, nlb=api_nlb)

        ssm_role = self.create_ssm_document_role(config=config, cluster_name=cluster.cluster_name, service_name=api_service.service_name)

        self.create_ecs_ssm_ecs_restrat_documentation(config=config, cluster_name=cluster.cluster_name, service_name=api_service.service_name, role_arn=ssm_role.role_arn)

        self.create_ecs_ssm_ecs_status_documentation(config=config, cluster_name=cluster.cluster_name, service_name=api_service.service_name, role_arn=ssm_role.role_arn)
