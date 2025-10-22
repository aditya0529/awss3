from aws_cdk import (
    aws_ec2 as ec2,
    aws_iam as iam,
    aws_logs as logs,
    Tags,
    RemovalPolicy,
)
from constructs import Construct
import uuid


class GpiJumpHost(Construct):

    def __init__(self,
                 scope: Construct,
                 construct_id: str,
                 stack_config,
                 vpc,
                 subnets,
                 region,
                 # network: MsgDltNetwork,
                 **kwargs
                 ):
        super().__init__(scope, construct_id, **kwargs)

        self._scope = scope
        self._stack_config = stack_config
        # self._network = network
        self._jump_host_instance = None
        self._jump_host_subnets = subnets
        self._jump_host_sg = None
        self._jump_host_role = None
        self._vpc = vpc
        self._region=region

    @property
    def jump_host_instance(self):
        return self._jump_host_instance

    @property
    def jump_host_sg(self) -> ec2.SecurityGroup:
        return self._jump_host_sg

    # def get_app_vpc(self) -> ec2.Vpc:
    #     return (self._vpc=ec2.Vpc.from_lookup(
    #         self,
    #         "sw-gpi-ptapii-vpc",
    #         vpc_id=self._stack_config['vpc_id_us-east-1']
    #     ))


    @property
    def jump_host_subnets(self):
        print(self._stack_config[f'workload_subnet_1_{self._region}'])
        subnet_selection = ec2.SubnetSelection(
            subnet_filters=[
                ec2.SubnetFilter.by_ids([
                    self._stack_config['workload_subnet_1_{self._region}']
                ])
            ]
        )
        # subnet_selection = {
        #     'subnets': [
        #         ec2.Subnet.from_subnet_attributes(
        #             self,
        #             str(uuid.uuid4()),
        #             subnet_id=self._stack_config['workload_subnet_1_us-east-1'],  # Your Subnet ID
        #             availability_zone="us-east-1a"       # Specify the availability zone
        #         )
        #         #for subnet_id in self._stack_config.egress_subnet_ids
        #     ]
        # }
        # return ec2.SubnetSelection(**subnet_selection)

        return subnet_selection

    def launch_jump_host(self):
        self._jump_host_role = self._create_role()
        self._jump_host_sg = self._create_sg()
        self._create_instance()
        return self

    def _create_instance(self):
        self._jump_host_instance = ec2.Instance(
            self,
            f"sw-gpi-ptappi-{self._stack_config['app_env']}-{self._region}-jump-host",
            instance_name=f"sw-gpi-ptappi-{self._stack_config['app_env']}-{self._region}-jump-host",
            instance_type=ec2.InstanceType.of(ec2.InstanceClass.T3,
                                              ec2.InstanceSize.MEDIUM),
            machine_image=ec2.LookupMachineImage(name="sw-cd-al2023baseami-0.2.0-patch.20250915T130208Z-ec2-main-aws"),
            vpc=self._vpc,
            vpc_subnets=self._jump_host_subnets,
            associate_public_ip_address=False,
            ssm_session_permissions=True,
            require_imdsv2=True,
            security_group=self._jump_host_sg,
            detailed_monitoring=True,
            role=self._jump_host_role
        )

        # _jump_host_cfn_instance = self._jump_host_instance.node.default_child
        # _jump_host_cfn_instance.cfn_options.metadata = {
        #     "guard": {
        #         "SuppressedRules": [
        #             "EC2_IMDSV2_CHECK",
        #             "EC2_INSTANCES_IN_VPC"
        #         ]
        #     }
        # }

        # _jump_host_cfn_instance.cfn_options.metadata = {
        #     "guard": {
        #         "SuppressedRules": ["EC2_INSTANCE_NO_PUBLIC_IP", "https://jira.swift.com:8443/browse/CCOE-8287"]
        #     }
        # }

        # _jump_host_cfn_instance.cfn_options.metadata = {
        #     "guard": {
        #         "SuppressedRules": ["INSTANCES_IN_VPC", "https://jira.swift.com:8443/browse/CCOE-8287"]
        #     }
        # }

        return self

    def _create_sg(self) -> ec2.SecurityGroup:
        sg = ec2.SecurityGroup(
            self,
            f"sw-gpi-ptappi-{self._stack_config['app_env']}-{self._region}-jump-host-sg",
            vpc=self._vpc,
            allow_all_ipv6_outbound=False,
            allow_all_outbound=False,
            description="Jump Host Security Group",
            security_group_name=f"sw-gpi-ptappi-{self._stack_config['app_env']}-{self._region}-jump-host-sg"
        )
        Tags.of(sg).add("Name", f"sw-gpi-ptappi-{self._stack_config['app_env']}-{self._region}-jump-host-sg")

        sg.add_egress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(443), "Full outbound access")

        _jump_host_sg_cfn_instance = sg.node.default_child
        _jump_host_sg_cfn_instance.cfn_options.metadata = {
            "guard": {
                "SuppressedRules": ["EC2_INSTANCE_NO_PUBLIC_IP", "https://jira.swift.com:8443/browse/CCOE-8287"]
            }
        }

        _jump_host_sg_cfn_instance.cfn_options.metadata = {
            "guard": {
                "SuppressedRules": ["INSTANCES_IN_VPC", "https://jira.swift.com:8443/browse/CCOE-8287"]
            }
        }

        return sg

    def _create_role(self) -> iam.Role:
        _instance_role = iam.Role(
            self,
            f"sw-gpi-ptappi-{self._stack_config['app_env']}-{self._region}-jump-host-role",
            role_name=f"sw-gpi-ptappi-{self._stack_config['app_env']}-{self._region}-jump-host-role",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com")
        )

        # Attach a policy to allow the EC2 instance to write logs to CloudWatch
        _instance_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("CloudWatchAgentServerPolicy")
        )
        _instance_role.add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name("AmazonECS_FullAccess"))
        _instance_role.add_managed_policy(iam.ManagedPolicy.from_managed_policy_arn(
            self,
            f"sw-gpi-ptappi-{self._stack_config['app_env']}-S3-foundational-pol",
            managed_policy_arn=f"arn:aws:iam::{self._stack_config['workload_account']}:policy/sw-foundational-s3-policy-main-aws"
        ))
        _instance_role.add_managed_policy(iam.ManagedPolicy.from_managed_policy_arn(
            self,
            f"sw-gpi-ptappi-{self._stack_config['app_env']}-kms-foundational-pol",
            managed_policy_arn=f"arn:aws:iam::{self._stack_config['workload_account']}:policy/sw-foundational-kms-secret-policy-main-aws"
        ))
        return _instance_role

