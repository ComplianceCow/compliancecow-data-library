import json
from logging import error
import os
from uuid import UUID
from typing import Any, TypeVar, Type, cast, List, Union, Optional
from datetime import datetime
from enum import Enum

from compliancecow.utils import constants, dictutils, headerutils, utils


class Subnet:
    subnet_id: str
    subnet_name: str

    def __init__(self, subnet_id: str, subnet_name: str) -> None:
        self.subnet_id = subnet_id
        self.subnet_name = subnet_name

    @staticmethod
    def from_dict(obj: Any) -> 'Subnet' or None:
        subnet = None
        if isinstance(obj, dict):
            subnet_id = subnet_name = None
            if dictutils.is_valid_key(obj, "subnetID"):
                subnet_id = utils.from_str(obj.get("subnetID"))
            if dictutils.is_valid_key(obj, "subnetName"):
                subnet_name = utils.from_str(obj.get("subnetName"))
            subnet = Subnet(subnet_id, subnet_name)
        return subnet

    def to_dict(self) -> dict:
        result: dict = {}
        if self.subnet_id:
            result["subnetID"] = utils.from_str(self.subnet_id)
        if self.subnet_name:
            result["subnetName"] = utils.from_str(self.subnet_name)
        return result


class Tags:
    azuretags: List[str]

    def __init__(self, azuretags: List[str]) -> None:
        self.azuretags = azuretags

    @staticmethod
    def from_dict(obj: Any) -> 'Tags' or None:
        tags = None
        if isinstance(obj, dict):
            azuretags = None
            if dictutils.is_valid_key(obj, "subnetName"):
                azuretags = utils.from_list(
                    utils.from_str, obj.get("azuretags"))
            tags = Tags(azuretags)
        return tags

    def to_dict(self) -> dict:
        result: dict = {}
        if self.azuretags:
            result["azuretags"] = utils.from_list(
                utils.from_str, self.azuretags)
        return result


class Vnet:
    vnet_id: str
    vnet_name: str
    subnets: List[Subnet]
    vnet_tags: Optional[Tags]

    def __init__(self, vnet_id: str, vnet_name: str, subnets: List[Subnet], vnet_tags: Optional[Tags]) -> None:
        self.vnet_id = vnet_id
        self.vnet_name = vnet_name
        self.subnets = subnets
        self.vnet_tags = vnet_tags

    @staticmethod
    def from_dict(obj: Any) -> 'Vnet' or None:
        vnet = None
        if isinstance(obj, dict):
            vnet_id = vnet_name = subnets = vnet_tags = None
            if dictutils.is_valid_key(obj, "vnetID"):
                vnet_id = utils.from_str(obj.get("vnetID"))
            if dictutils.is_valid_key(obj, "vnetName"):
                vnet_name = utils.from_str(obj.get("vnetName"))
            if dictutils.is_valid_array(obj, "subnets"):
                subnets = utils.from_list(Subnet.from_dict, obj.get("subnets"))
            if dictutils.is_valid_key(obj, "vnetTags"):
                vnet_tags = utils.from_union(
                    [Tags.from_dict, utils.from_none], obj.get("vnetTags"))
            vnet = Vnet(vnet_id, vnet_name, subnets, vnet_tags)
        return vnet

    def to_dict(self) -> dict:
        result: dict = {}
        if self.vnet_id:
            result["vnetID"] = utils.from_str(self.vnet_id)
        if self.vnet_name:
            result["vnetName"] = utils.from_str(self.vnet_name)
        if self.subnets:
            result["subnets"] = utils.from_list(
                lambda x: utils.to_class(Subnet, x), self.subnets)
        if self.vnet_tags:
            result["vnetTags"] = utils.from_union(
                [lambda x: utils.to_class(Tags, x), utils.from_none], self.vnet_tags)
        return result


class Cluster:
    cluster_name: str
    cluster_id: str
    vnets: List[Vnet]
    is_validated: bool
    updated_at: str
    created_at: str
    other_credential: None

    def __init__(self, cluster_name: str, cluster_id: str, vnets: List[Vnet], is_validated: bool, updated_at: str, created_at: str, other_credential: None) -> None:
        self.cluster_name = cluster_name
        self.cluster_id = cluster_id
        self.vnets = vnets
        self.is_validated = is_validated
        self.updated_at = updated_at
        self.created_at = created_at
        self.other_credential = other_credential

    @staticmethod
    def from_dict(obj: Any) -> 'Cluster':
        cluster = None
        if isinstance(obj, dict):
            cluster_name = cluster_id = vnets = is_validated = updated_at = created_at = other_credential = None
            if dictutils.is_valid_key(obj, "clusterName"):
                cluster_name = utils.from_str(obj.get("clusterName"))
            if dictutils.is_valid_key(obj, "clusterID"):
                cluster_id = utils.from_str(obj.get("clusterID"))
            if dictutils.is_valid_array(obj, "vnets"):
                vnets = utils.from_list(Vnet.from_dict, obj.get("vnets"))
            if dictutils.is_valid_key(obj, "isValidated"):
                is_validated = utils.from_bool(obj.get("isValidated"))
            if dictutils.is_valid_key(obj, "updatedAt"):
                updated_at = utils.from_str(obj.get("updatedAt"))
            if dictutils.is_valid_key(obj, "createdAt"):
                created_at = utils.from_str(obj.get("createdAt"))
            if dictutils.is_valid_key(obj, "otherCredential"):
                other_credential = utils.from_none(obj.get("otherCredential"))
            cluster = Cluster(cluster_name, cluster_id, vnets,
                              is_validated, updated_at, created_at, other_credential)
        return cluster

    def to_dict(self) -> dict:
        result: dict = {}
        if self.cluster_name:
            result["clusterName"] = utils.from_str(self.cluster_name)
        if self.cluster_id:
            result["clusterID"] = utils.from_str(self.cluster_id)
        if self.vnets:
            result["vnets"] = utils.from_list(
                lambda x: utils.to_class(Vnet, x), self.vnets)
        if self.is_validated:
            result["isValidated"] = utils.from_bool(self.is_validated)
        if self.updated_at:
            result["updatedAt"] = utils.from_str(self.updated_at)
        if self.created_at:
            result["createdAt"] = utils.from_str(self.created_at)
        if self.other_credential:
            result["otherCredential"] = utils.from_none(self.other_credential)
        return result


class ResourceGroup:
    resource_group_name: str
    resource_group_id: str
    resource_group_location: str
    vnets: Optional[List[Vnet]]
    clusters: Optional[List[Cluster]]
    resource_group_tags: Optional[Tags]

    def __init__(self, resource_group_name: str, resource_group_id: str, resource_group_location: str, vnets: Optional[List[Vnet]], clusters: Optional[List[Cluster]], resource_group_tags: Optional[Tags]) -> None:
        self.resource_group_name = resource_group_name
        self.resource_group_id = resource_group_id
        self.resource_group_location = resource_group_location
        self.vnets = vnets
        self.clusters = clusters
        self.resource_group_tags = resource_group_tags

    @staticmethod
    def from_dict(obj: Any) -> 'ResourceGroup' or None:
        resource_group = None
        if isinstance(obj, dict):
            resource_group_name = resource_group_id = resource_group_location = vnets = clusters = resource_group_tags = None
            if dictutils.is_valid_key(obj, "resourceGroupName"):
                resource_group_name = utils.from_str(
                    obj.get("resourceGroupName"))
            if dictutils.is_valid_key(obj, "resourceGroupID"):
                resource_group_id = utils.from_str(obj.get("resourceGroupID"))
            if dictutils.is_valid_key(obj, "resourceGroupLocation"):
                resource_group_location = utils.from_str(
                    obj.get("resourceGroupLocation"))
            if dictutils.is_valid_array(obj, "vnets"):
                vnets = utils.from_union([lambda x: utils.from_list(
                    Vnet.from_dict, x), utils.from_none], obj.get("vnets"))
            if dictutils.is_valid_array(obj, "clusters"):
                clusters = utils.from_union([lambda x: utils.from_list(
                    Cluster.from_dict, x), utils.from_none], obj.get("clusters"))
            if dictutils.is_valid_key(obj, "resourceGroupTags"):
                resource_group_tags = utils.from_union(
                    [Tags.from_dict, utils.from_none], obj.get("resourceGroupTags"))
            resource_group = ResourceGroup(
                resource_group_name, resource_group_id, resource_group_location, vnets, clusters, resource_group_tags)
        return resource_group

    def to_dict(self) -> dict:
        result: dict = {}
        if self.resource_group_name:
            result["resourceGroupName"] = utils.from_str(
                self.resource_group_name)
        if self.resource_group_id:
            result["resourceGroupID"] = utils.from_str(self.resource_group_id)
        if self.resource_group_location:
            result["resourceGroupLocation"] = utils.from_str(
                self.resource_group_location)
        if self.vnets:
            result["vnets"] = utils.from_union([lambda x: utils.from_list(
                lambda x: utils.to_class(Vnet, x), x), utils.from_none], self.vnets)
        if self.clusters:
            result["clusters"] = utils.from_union([lambda x: utils.from_list(
                lambda x: utils.to_class(Cluster, x), x), utils.from_none], self.clusters)
        if self.resource_group_tags:
            result["resourceGroupTags"] = utils.from_union(
                [lambda x: utils.to_class(Tags, x), utils.from_none], self.resource_group_tags)
        return result


class Subscription:
    id: str
    subscription_id: UUID
    client_id: str
    client_secret: str
    tenant_id: UUID
    is_validated: bool
    resource_groups: List[ResourceGroup]
    sensitive_data_path: str
    recordguid: str
    rowno: int
    recordstatus: str
    created_at: str
    last_updated_at: str
    created_by: UUID
    last_updated_by: UUID

    def __init__(self, id: str, subscription_id: UUID, client_id: str, client_secret: str, tenant_id: UUID, is_validated: bool, resource_groups: List[ResourceGroup], sensitive_data_path: str, recordguid: str, rowno: int, recordstatus: str, created_at: str, last_updated_at: str, created_by: UUID, last_updated_by: UUID) -> None:
        self.id = id
        self.subscription_id = subscription_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.tenant_id = tenant_id
        self.is_validated = is_validated
        self.resource_groups = resource_groups
        self.sensitive_data_path = sensitive_data_path
        self.recordguid = recordguid
        self.rowno = rowno
        self.recordstatus = recordstatus
        self.created_at = created_at
        self.last_updated_at = last_updated_at
        self.created_by = created_by
        self.last_updated_by = last_updated_by

    @staticmethod
    def from_dict(obj: Any) -> 'Subscription' or None:
        subscription = None
        if isinstance(obj, dict):
            id = subscription_id = client_id = client_secret = tenant_id = is_validated = resource_groups = sensitive_data_path = recordguid = rowno = recordstatus = created_at = last_updated_at = created_by = last_updated_by = None
            if dictutils.is_valid_key(obj, "id"):
                id = utils.from_str(obj.get("id"))
            if dictutils.is_valid_key(obj, "subscriptionID"):
                subscription_id = UUID(obj.get("subscriptionID"))
            if dictutils.is_valid_key(obj, "clientID"):
                client_id = utils.from_str(obj.get("clientID"))
            if dictutils.is_valid_key(obj, "clientSecret"):
                client_secret = utils.from_str(obj.get("clientSecret"))
            if dictutils.is_valid_key(obj, "tenantID"):
                tenant_id = UUID(obj.get("tenantID"))
            if dictutils.is_valid_key(obj, "isValidated"):
                is_validated = utils.from_bool(obj.get("isValidated"))
            if dictutils.is_valid_array(obj, "resourceGroups"):
                resource_groups = utils.from_list(
                    ResourceGroup.from_dict, obj.get("resourceGroups"))
            if dictutils.is_valid_key(obj, "sensitiveDataPath"):
                sensitive_data_path = utils.from_str(
                    obj.get("sensitiveDataPath"))
            if dictutils.is_valid_key(obj, "recordguid__"):
                recordguid = utils.from_str(obj.get("recordguid__"))
            if dictutils.is_valid_key(obj, "rowno__"):
                rowno = utils.from_int(obj.get("rowno__"))
            if dictutils.is_valid_key(obj, "recordstatus__"):
                recordstatus = utils.from_str(obj.get("recordstatus__"))
            if dictutils.is_valid_key(obj, "created_at__"):
                created_at = utils.from_str(obj.get("created_at__"))
            if dictutils.is_valid_key(obj, "last_updated_at__"):
                last_updated_at = utils.from_str(obj.get("last_updated_at__"))
            if dictutils.is_valid_key(obj, "created_by__"):
                created_by = UUID(obj.get("created_by__"))
            if dictutils.is_valid_key(obj, "last_updated_by__"):
                last_updated_by = UUID(obj.get("last_updated_by__"))
            subscription = Subscription(id, subscription_id, client_id, client_secret, tenant_id, is_validated, resource_groups,
                                        sensitive_data_path, recordguid, rowno, recordstatus, created_at, last_updated_at, created_by, last_updated_by)
        return subscription

    def to_dict(self) -> dict:
        result: dict = {}
        if self.id:
            result["id"] = utils.from_str(self.id)
        if self.subscription_id:
            result["subscriptionID"] = str(self.subscription_id)
        if self.client_id:
            result["clientID"] = utils.from_str(self.client_id)
        if self.client_secret:
            result["clientSecret"] = utils.from_str(self.client_secret)
        if self.tenant_id:
            result["tenantID"] = str(self.tenant_id)
        if self.is_validated:
            result["isValidated"] = utils.from_bool(self.is_validated)
        if self.resource_groups:
            result["resourceGroups"] = utils.from_list(
                lambda x: utils.to_class(ResourceGroup, x), self.resource_groups)
        if self.sensitive_data_path:
            result["sensitiveDataPath"] = utils.from_str(
                self.sensitive_data_path)
        if self.recordguid:
            result["recordguid__"] = utils.from_str(self.recordguid)
        if self.rowno:
            result["rowno__"] = utils.from_int(self.rowno)
        if self.recordstatus:
            result["recordstatus__"] = utils.from_str(self.recordstatus)
        if self.created_at:
            result["created_at__"] = utils.from_str(self.created_at)
        if self.last_updated_at:
            result["last_updated_at__"] = utils.from_str(self.last_updated_at)
        if self.created_by:
            result["created_by__"] = str(self.created_by)
        if self.last_updated_by:
            result["last_updated_by__"] = str(self.last_updated_by)
        return result


class Configuration:
    id: UUID
    name: str
    description: str
    git_commit_hash: str
    type: str
    cloud_type: str
    subscriptions: List[Subscription]
    plan_id: UUID
    plan_instance_id: UUID
    domain_id: UUID
    org_id: UUID
    group_id: UUID
    created_by: UUID
    status: str
    availability_level: str
    created_at: datetime
    last_updated_by: UUID
    last_updated_at: datetime

    def __init__(self, id: UUID, name: str, description: str, git_commit_hash: str, type: str, cloud_type: str, subscriptions: List[Subscription], plan_id: UUID, plan_instance_id: UUID, domain_id: UUID, org_id: UUID, group_id: UUID, created_by: UUID, status: str, availability_level: str, created_at: datetime, last_updated_by: UUID, last_updated_at: datetime) -> None:
        self.id = id
        self.name = name
        self.description = description
        self.git_commit_hash = git_commit_hash
        self.type = type
        self.cloud_type = cloud_type
        self.subscriptions = subscriptions
        self.plan_id = plan_id
        self.plan_instance_id = plan_instance_id
        self.domain_id = domain_id
        self.org_id = org_id
        self.group_id = group_id
        self.created_by = created_by
        self.status = status
        self.availability_level = availability_level
        self.created_at = created_at
        self.last_updated_by = last_updated_by
        self.last_updated_at = last_updated_at

    @staticmethod
    def from_dict(obj: Any) -> 'Configuration' or None:
        configuration = None
        if isinstance(obj, dict):
            id = name = description = git_commit_hash = type = cloud_type = subscriptions = plan_id = plan_instance_id = domain_id = org_id = group_id = created_by = status = availability_level = created_at = last_updated_by = last_updated_at = None
            if dictutils.is_valid_key(obj, "id"):
                id = UUID(obj.get("id"))
            if dictutils.is_valid_key(obj, "name"):
                name = utils.from_str(obj.get("name"))
            if dictutils.is_valid_key(obj, "description"):
                description = utils.from_str(obj.get("description"))
            if dictutils.is_valid_key(obj, "gitCommitHash"):
                git_commit_hash = utils.from_str(obj.get("gitCommitHash"))
            if dictutils.is_valid_key(obj, "type"):
                type = utils.from_str(obj.get("type"))
            if dictutils.is_valid_key(obj, "cloudType"):
                cloud_type = utils.from_str(obj.get("cloudType"))
            if dictutils.is_valid_array(obj, "subscriptions"):
                subscriptions = utils.from_list(
                    Subscription.from_dict, obj.get("subscriptions"))
            if dictutils.is_valid_key(obj, "planID"):
                plan_id = UUID(obj.get("planID"))
            if dictutils.is_valid_key(obj, "planInstanceID"):
                plan_instance_id = UUID(obj.get("planInstanceID"))
            if dictutils.is_valid_key(obj, "domainID"):
                domain_id = UUID(obj.get("domainID"))
            if dictutils.is_valid_key(obj, "orgID"):
                org_id = UUID(obj.get("orgID"))
            if dictutils.is_valid_key(obj, "groupID"):
                group_id = UUID(obj.get("groupID"))
            if dictutils.is_valid_key(obj, "createdBy"):
                created_by = UUID(obj.get("createdBy"))
            if dictutils.is_valid_key(obj, "status"):
                status = utils.from_str(obj.get("status"))
            if dictutils.is_valid_key(obj, "availabilityLevel"):
                availability_level = utils.from_str(
                    obj.get("availabilityLevel"))
            if dictutils.is_valid_key(obj, "createdAt"):
                created_at = utils.from_datetime(obj.get("createdAt"))
            if dictutils.is_valid_key(obj, "lastUpdatedBy"):
                last_updated_by = UUID(obj.get("lastUpdatedBy"))
            if dictutils.is_valid_key(obj, "lastUpdatedAt"):
                last_updated_at = utils.from_datetime(obj.get("lastUpdatedAt"))
            configuration = Configuration(id, name, description, git_commit_hash, type, cloud_type, subscriptions, plan_id, plan_instance_id,
                                          domain_id, org_id, group_id, created_by, status, availability_level, created_at, last_updated_by, last_updated_at)
        return configuration

    def to_dict(self) -> dict:
        result: dict = {}
        if self.id:
            result["id"] = str(self.id)
        if self.name:
            result["name"] = utils.from_str(self.name)
        if self.description:
            result["description"] = utils.from_str(self.description)
        if self.git_commit_hash:
            result["gitCommitHash"] = utils.from_str(self.git_commit_hash)
        if self.type:
            result["type"] = utils.from_str(self.type)
        if self.cloud_type:
            result["cloudType"] = utils.from_str(self.cloud_type)
        if self.subscriptions:
            result["subscriptions"] = utils.from_list(
                lambda x: utils.to_class(Subscription, x), self.subscriptions)
        if self.plan_id:
            result["planID"] = str(self.plan_id)
        if self.plan_instance_id:
            result["planInstanceID"] = str(self.plan_instance_id)
        if self.domain_id:
            result["domainID"] = str(self.domain_id)
        if self.org_id:
            result["orgID"] = str(self.org_id)
        if self.group_id:
            result["groupID"] = str(self.group_id)
        if self.created_by:
            result["createdBy"] = str(self.created_by)
        if self.status:
            result["status"] = utils.from_str(self.status)
        if self.availability_level:
            result["availabilityLevel"] = utils.from_str(
                self.availability_level)
        if self.created_at:
            result["createdAt"] = self.created_at.isoformat()
        if self.last_updated_by:
            result["lastUpdatedBy"] = str(self.last_updated_by)
        if self.last_updated_at:
            result["lastUpdatedAt"] = self.last_updated_at.isoformat()
        return result


def configuration_from_dict(s: Any) -> Configuration:
    return Configuration.from_dict(s)


def configuration_to_dict(x: Configuration) -> Any:
    return utils.to_class(Configuration, x)
