from aws_cdk import (
    aws_ec2 as ec2,
    aws_iam as iam,
    aws_logs as logs,
    Tags,
    RemovalPolicy,
)
from constructs import Construct

from config.config import StackConfig
from construct.network import MsgDltNetwork
from construct.efs_fs import MsgDltEfs
from utils.utils import Utils
from construct.backup_plan_ec2 import BackupPlanForEc2

class MsgDltJumpHost(Construct):

    def __init__(self,
                 scope: Construct,
                 construct_id: str,
                 stack_config: StackConfig,
                 network: MsgDltNetwork,
                 efs_fs: MsgDltEfs,
                 **kwargs
                 ):
        super().__init__(scope, construct_id, **kwargs)

        self._scope = scope
        self._stack_config = stack_config
        self._network = network
        self._efs_fs = efs_fs
        self._jump_host_instance = None
        self._jump_host_sg = None
        self._jump_host_role = None

    @property
    def jump_host_instance(self):
        return self._jump_host_instance

    @property
    def jump_host_sg(self) -> ec2.SecurityGroup:
        return self._jump_host_sg

    def launch_jump_host(self):
        self._jump_host_role = self._create_role()
        self._jump_host_sg = self._create_sg()
        self._create_instance()
        return self

    def _create_instance(self):
        self._jump_host_instance = ec2.Instance(
            self,
            Utils.resource_id_helper('jump-host'),
            instance_name=Utils.resource_name_helper('jump-host'),
            instance_type=ec2.InstanceType.of(ec2.InstanceClass.T3,
                                              ec2.InstanceSize.MEDIUM),
            machine_image=ec2.LookupMachineImage(name="sw-cd-ec2al2baseami-0.16.0-patch.20250901T130307Z-ec2-main-aws"),
            vpc=self._network.vpc,
            vpc_subnets=self._network.jump_host_subnets,
            associate_public_ip_address=False,
            ssm_session_permissions=True,
            require_imdsv2=True,
            security_group=self._jump_host_sg,
            detailed_monitoring=True,
            role=self._jump_host_role
        )

        self._jump_host_instance.user_data.add_commands(
            "sudo yum install -y amazon-efs-utils",
            "efs_id=" + self._efs_fs.file_system.file_system_id,
            "efs_mount_path=/app",
            'sudo mkdir -p "${efs_mount_path}"',
            'sudo mount -t efs -o tls,iam "${efs_id}":/ "${efs_mount_path}"',
            'echo ${efs_id}:/ ${efs_mount_path} efs defaults,_netdev 0 0 | sudo tee -a /etc/fstab',
            )
        _jump_host_cfn_instance = self._jump_host_instance.node.default_child
        _jump_host_cfn_instance.cfn_options.metadata = {
            "guard": {
                "SuppressedRules": [
                    "EC2_IMDSV2_CHECK",
                    "EC2_INSTANCES_IN_VPC"
                ]
            }
        }
        self._efs_fs.file_system.connections.allow_default_port_from(self._jump_host_instance)

        #backup ec2 instance
        # BackupPlanForEc2(self, Utils.resource_id_helper("backup-jumphost"), self._jump_host_instance)

        return self

    def _create_sg(self) -> ec2.SecurityGroup:
        sg = ec2.SecurityGroup(
            self,
            Utils.resource_id_helper("jump-host-sg"),
            vpc=self._network.vpc,
            allow_all_ipv6_outbound=False,
            allow_all_outbound=False,
            description="Jump Host Security Group",
            security_group_name=Utils.resource_name_helper("jump-host-sg")
        )
        Tags.of(sg).add("Name", Utils.resource_name_helper("jump-host-sg"))

        sg.add_egress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(443), "Full outbound access")
        for container_config in self._stack_config.containers_config:
            sg.add_egress_rule(
                ec2.Peer.ipv4(self._network.vpc.vpc_cidr_block),
                ec2.Port.tcp(container_config.host_port),
                f"Access to {container_config.name}"
            )
        return sg

    def _create_role(self) -> iam.Role:
        _instance_role = iam.Role(
            self,
            Utils.resource_id_helper('jump-host-role'),
            role_name=Utils.resource_name_helper('jump-host-role'),
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com")
        )

        # Attach a policy to allow the EC2 instance to write logs to CloudWatch
        _instance_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("CloudWatchAgentServerPolicy")
        )
        _instance_role.add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name("AmazonECS_FullAccess"))
        _instance_role.add_managed_policy(iam.ManagedPolicy.from_managed_policy_arn(
            self,
            Utils.resource_name_helper("kms-foundational-pol"),
            managed_policy_arn=f"arn:aws:iam::{self._stack_config.bootstrap_config.workload_account}:policy/sw-foundational-kms-secret-policy-main-aws"
        ))
        self._efs_fs.file_system.grant_read_write(_instance_role)
        self._efs_fs.file_system.grant_root_access(_instance_role)
        return _instance_role