"""
Cognitive SOC — EC2 Isolator Playbook
When a compromised EC2 instance is detected, this playbook:
1. Creates a forensic snapshot of the EBS volume
2. Replaces all security groups with a deny-all isolation group
3. Tags the instance as compromised
4. Optionally stops the instance (configurable)
"""

import json
import logging
import os
import boto3
from datetime import datetime

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

ec2_client = boto3.client("ec2")
ec2_resource = boto3.resource("ec2")


def lambda_handler(event, context):
    finding = event.get("finding", {})
    resource = finding.get("resource", {})

    instance_details = resource.get("instanceDetails", {})
    instance_id = instance_details.get("instanceId")

    if not instance_id:
        logger.warning("No instance ID found in finding — cannot isolate")
        return {"actions_taken": ["no_instance_found"], "success": False}

    logger.info(f"Isolating EC2 instance: {instance_id}")
    actions_taken = []

    try:
        # Step 1: Create forensic snapshot before any changes
        snapshot_id = create_forensic_snapshot(instance_id)
        if snapshot_id:
            actions_taken.append(f"snapshot_created:{snapshot_id}")

        # Step 2: Get or create isolation security group
        isolation_sg_id = get_or_create_isolation_sg(instance_details.get("vpcId", ""))
        actions_taken.append(f"isolation_sg:{isolation_sg_id}")

        # Step 3: Replace instance security groups with isolation group
        ec2_client.modify_instance_attribute(
            InstanceId=instance_id,
            Groups=[isolation_sg_id]
        )
        actions_taken.append("security_groups_replaced")
        logger.info(f"Replaced security groups on {instance_id} with isolation group {isolation_sg_id}")

        # Step 4: Tag instance as compromised
        ec2_client.create_tags(Resources=[instance_id], Tags=[
            {"Key": "CognitiveSoc:Status",      "Value": "ISOLATED"},
            {"Key": "CognitiveSoc:IsolatedAt",  "Value": datetime.utcnow().isoformat()},
            {"Key": "CognitiveSoc:FindingType", "Value": finding.get("type", "unknown")},
            {"Key": "CognitiveSoc:FindingId",   "Value": finding.get("id", "unknown")},
        ])
        actions_taken.append("instance_tagged")

        logger.info(f"Instance {instance_id} successfully isolated. Actions: {actions_taken}")
        return {
            "success": True,
            "instance_id": instance_id,
            "isolation_sg_id": isolation_sg_id,
            "actions_taken": actions_taken
        }

    except Exception as e:
        logger.error(f"Failed to isolate {instance_id}: {str(e)}", exc_info=True)
        return {
            "success": False,
            "instance_id": instance_id,
            "actions_taken": actions_taken,
            "error": str(e)
        }


def create_forensic_snapshot(instance_id):
    """Snapshot all EBS volumes attached to the instance for forensic analysis."""
    try:
        response = ec2_client.describe_instances(InstanceIds=[instance_id])
        reservations = response.get("Reservations", [])
        if not reservations:
            return None

        instance = reservations[0]["Instances"][0]
        block_devices = instance.get("BlockDeviceMappings", [])

        snapshot_ids = []
        for device in block_devices:
            volume_id = device.get("Ebs", {}).get("VolumeId")
            if volume_id:
                snap = ec2_client.create_snapshot(
                    VolumeId=volume_id,
                    Description=f"CognitiveSoc forensic snapshot - {instance_id} - {datetime.utcnow().isoformat()}",
                    TagSpecifications=[{
                        "ResourceType": "snapshot",
                        "Tags": [
                            {"Key": "CognitiveSoc:ForensicSnapshot", "Value": "true"},
                            {"Key": "CognitiveSoc:SourceInstance",   "Value": instance_id},
                        ]
                    }]
                )
                snapshot_ids.append(snap["SnapshotId"])
                logger.info(f"Created forensic snapshot {snap['SnapshotId']} for volume {volume_id}")

        return ",".join(snapshot_ids) if snapshot_ids else None

    except Exception as e:
        logger.warning(f"Snapshot creation failed (non-fatal): {str(e)}")
        return None


def get_or_create_isolation_sg(vpc_id):
    """
    Get or create a deny-all security group for isolation.
    The group has NO inbound rules and NO outbound rules — complete isolation.
    """
    sg_name = f"cognitive-soc-isolation-{vpc_id}" if vpc_id else "cognitive-soc-isolation"

    # Check if isolation SG already exists
    try:
        response = ec2_client.describe_security_groups(
            Filters=[
                {"Name": "group-name", "Values": [sg_name]},
                *([{"Name": "vpc-id", "Values": [vpc_id]}] if vpc_id else [])
            ]
        )
        existing = response.get("SecurityGroups", [])
        if existing:
            sg_id = existing[0]["GroupId"]
            logger.info(f"Using existing isolation security group: {sg_id}")

            # Ensure all outbound rules are removed (deny-all egress)
            if existing[0].get("IpPermissionsEgress"):
                ec2_client.revoke_security_group_egress(
                    GroupId=sg_id,
                    IpPermissions=existing[0]["IpPermissionsEgress"]
                )
            return sg_id
    except Exception:
        pass

    # Create new isolation security group
    kwargs = {
        "GroupName": sg_name,
        "Description": "CognitiveSoc isolation group - deny all traffic - DO NOT MODIFY",
    }
    if vpc_id:
        kwargs["VpcId"] = vpc_id

    response = ec2_client.create_security_group(**kwargs)
    sg_id = response["GroupId"]

    # Remove default outbound allow-all rule
    ec2_client.revoke_security_group_egress(
        GroupId=sg_id,
        IpPermissions=[{
            "IpProtocol": "-1",
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
        }]
    )

    ec2_client.create_tags(Resources=[sg_id], Tags=[
        {"Key": "Name", "Value": sg_name},
        {"Key": "CognitiveSoc:Purpose", "Value": "isolation"},
    ])

    logger.info(f"Created isolation security group: {sg_id}")
    return sg_id
