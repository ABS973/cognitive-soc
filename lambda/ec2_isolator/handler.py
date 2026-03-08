"""
Cognitive SOC — EC2 Isolator Playbook
1. Creates forensic snapshot
2. Replaces all security groups with deny-all
3. Tags instance as compromised
"""
import json, logging, os, boto3
from datetime import datetime

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))
ec2_client = boto3.client("ec2")

def lambda_handler(event, context):
    finding = event.get("finding", {})
    instance_id = finding.get("resource", {}).get("instanceDetails", {}).get("instanceId")
    if not instance_id:
        return {"actions_taken": ["no_instance_found"], "success": False}

    logger.info(f"Isolating EC2: {instance_id}")
    actions_taken = []

    snapshot_id = create_forensic_snapshot(instance_id)
    if snapshot_id:
        actions_taken.append(f"snapshot_created:{snapshot_id}")

    isolation_sg_id = get_or_create_isolation_sg(
        finding.get("resource", {}).get("instanceDetails", {}).get("vpcId", "")
    )
    ec2_client.modify_instance_attribute(InstanceId=instance_id, Groups=[isolation_sg_id])
    actions_taken.append("security_groups_replaced")

    ec2_client.create_tags(Resources=[instance_id], Tags=[
        {"Key": "CognitiveSoc:Status",      "Value": "ISOLATED"},
        {"Key": "CognitiveSoc:IsolatedAt",  "Value": datetime.utcnow().isoformat()},
        {"Key": "CognitiveSoc:FindingType", "Value": finding.get("type", "unknown")},
    ])
    actions_taken.append("instance_tagged")
    return {"success": True, "instance_id": instance_id, "actions_taken": actions_taken}

def create_forensic_snapshot(instance_id):
    try:
        response = ec2_client.describe_instances(InstanceIds=[instance_id])
        instance = response["Reservations"][0]["Instances"][0]
        ids = []
        for device in instance.get("BlockDeviceMappings", []):
            vid = device.get("Ebs", {}).get("VolumeId")
            if vid:
                snap = ec2_client.create_snapshot(VolumeId=vid,
                    Description=f"CognitiveSoc forensic - {instance_id}")
                ids.append(snap["SnapshotId"])
        return ",".join(ids)
    except Exception as e:
        logger.warning(f"Snapshot failed (non-fatal): {e}")
        return None

def get_or_create_isolation_sg(vpc_id):
    sg_name = f"cognitive-soc-isolation-{vpc_id}" if vpc_id else "cognitive-soc-isolation"
    try:
        r = ec2_client.describe_security_groups(Filters=[{"Name": "group-name", "Values": [sg_name]}])
        if r["SecurityGroups"]:
            return r["SecurityGroups"][0]["GroupId"]
    except Exception:
        pass
    kwargs = {"GroupName": sg_name, "Description": "CognitiveSoc isolation - deny all"}
    if vpc_id:
        kwargs["VpcId"] = vpc_id
    r = ec2_client.create_security_group(**kwargs)
    sg_id = r["GroupId"]
    ec2_client.revoke_security_group_egress(GroupId=sg_id,
        IpPermissions=[{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    return sg_id
