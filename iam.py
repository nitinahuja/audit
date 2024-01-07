from utils.session import Utils
from collections import defaultdict


class IAM:

    @staticmethod
    def get_attached_entity_policy(service: object, policy_arn: str) -> dict:
        '''Gets policy document for attached/managed policies'''
        policy = service.get_policy(PolicyArn=policy_arn)
        policy_details = service.get_policy_version(
            PolicyArn=policy["Policy"]["Arn"], VersionId=policy["Policy"]["DefaultVersionId"])
        return policy_details["PolicyVersion"]["Document"]

    @staticmethod
    def get_user_policy(service: object, user_name: str, policy_name: str) -> dict:
        '''Gets the policy action and resource sections for inline policies'''

        policy = service.get_user_policy(
            UserName=user_name, PolicyName=policy_name)
        # Return the PolicyDocument
        if "PolicyDocument" in policy:
            return policy["PolicyDocument"]

    def users(self, iam_client: object) -> dict:
        """Gets IAM users and policies attached to them. 
        Both Inline and managed policies are returned.

        Args:
            iam_client (object): The IAM client

        Returns:
            dict: users and their policies
        """
        output = defaultdict(dict)
        # Iterate through all users in account.
        for user in Utils.paginate(iam_client, "list_users", "Users"):
            output[user["UserName"]] = user
            # Get inline policies
            output[user["UserName"]]["policy"] = defaultdict(dict)
            output[user["UserName"]]["policy"]["inline"] = defaultdict(dict)
            output[user["UserName"]]["policy"]["managed"] = defaultdict(dict)
            for policy_name in Utils.paginate(iam_client, "list_user_policies", "PolicyNames", UserName=user["UserName"]):
                output[user["UserName"]]["policy"]["inline"] = self.get_user_policy(
                    iam_client, user["UserName"], policy_name)

            # now get the attached(managed) policies
            for policy in Utils.paginate(iam_client, "list_attached_user_policies", "AttachedPolicies", UserName=user["UserName"]):
                output[user["UserName"]]["policy"]["managed"] = self.get_attached_entity_policy(
                    iam_client, policy["PolicyArn"])

        return output

    def groups(self, iam_client) -> dict:
        """_summary_

        Args:
            iam_client (object): the IAM client

        Returns:
            dict: Group information and policies for account
        """
        output = {}

        for group in Utils.paginate(iam_client, "list_groups", "Groups"):
            output[group["GroupName"]] = group
            # Users in this group
            output[group["GroupName"]]["users"] = [user for user in Utils.paginate(
                iam_client, "get_group", "Users", GroupName=group["GroupName"])]

            output[group["GroupName"]]["policy"] = defaultdict(dict)
            output[group["GroupName"]]["policy"]["inline"] = defaultdict(dict)
            output[group["GroupName"]]["policy"]["managed"] = defaultdict(dict)

            # Policies attached to this group - Inline
            for policy in Utils.paginate(iam_client, "list_group_policies", "PolicyNames", GroupName=group["GroupName"]):
                output[group["GroupName"]]["policy"]["inline"] = Utils.paginate(
                    iam_client, "get_group_policy", "PolicyDocument", GroupName=group["GroupName"], PolicyName=policy)

            # Managed group Policies
            for policy in Utils.paginate(iam_client, "list_attached_group_policies", "AttachedPolicies", GroupName=group["GroupName"]):
                output[group["GroupName"]]["policy"]["managed"] = self.get_attached_entity_policy(
                    iam_client, policy["PolicyArn"])

        return output


if __name__ == '__main__':
    
    session = Utils.get_session()
    iam_client = session.client('iam')

    iam = IAM()
    # users = iam.users(iam_client)
    groups = iam.groups(iam_client)
