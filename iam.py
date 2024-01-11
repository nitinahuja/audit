""" Imports AWS IAM User and Group information
"""

import typing
from collections import defaultdict
import datetime

import tabulate

from utils.session import Utils

class IAM:
    '''Implements the user and group information methods
    '''

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

    @staticmethod
    def get_group_policy(service: object, group_name: str, policy_name: str) -> dict:
        '''Gets the policy action and resource sections for inline policies'''

        policy = service.get_group_policy(
            GroupName=group_name, PolicyName=policy_name)
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
                output[user["UserName"]]["policy"]["inline"].setdefault(policy_name, []).append(self.get_user_policy(
                    iam_client, user["UserName"], policy_name))

            # now get the attached(managed) policies
            for policy in Utils.paginate(iam_client, "list_attached_user_policies", "AttachedPolicies", UserName=user["UserName"]):
                output[user["UserName"]]["policy"]["managed"].setdefault(policy["PolicyName"], []).append(self.get_attached_entity_policy(
                    iam_client, policy["PolicyArn"]))

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
            for policy_name in Utils.paginate(iam_client, "list_group_policies", "PolicyNames", GroupName=group["GroupName"]):
                output[group["GroupName"]]["policy"]["inline"].setdefault(policy_name, []).append(self.get_group_policy(
                    iam_client, group_name=group["GroupName"], policy_name=policy_name))

            # Managed group Policies
            for policy in Utils.paginate(iam_client, "list_attached_group_policies", "AttachedPolicies", GroupName=group["GroupName"]):
                output[group["GroupName"]]["policy"]["managed"].setdefault(policy["PolicyName"], []).append(self.get_attached_entity_policy(
                    iam_client, policy["PolicyArn"]))

        return output

    def _format_policy_markdown(self, policies:dict, file:typing.TextIO)->None:

        for policy, statements in policies["policy"]["inline"].items():
            print(f"### Policy(inline) {policy} \n", file=file)
            print(tabulate.tabulate(statements[0]["Statement"], headers="keys", tablefmt="pipe"), file=file)

        for policy, statements in policies["policy"]["managed"].items():
            print(f"### Policy(managed) {policy} \n", file=file)
            print(tabulate.tabulate(statements[0]["Statement"], headers="keys", tablefmt="pipe"), file=file)

        
    def format_user_markdown(self, users: dict, filename: str) -> None:
        """Print out user details to markdown file - will overwrite existing file

        Args:
            users (dict): _description_
            filename (str): _description_
        """
        with open(filename, 'w') as f:
            print(f'File Generated at {datetime.datetime.now()}')
            print("# Users \n", file=f)
            for username, user in users.items():
                print(f'## user: {username} \n\n '
                      f'created: {user["CreateDate"]} \n '
                      f'password last used: {user["PasswordLastUsed"] if "PasswordLastUsed" in user else "Not console enabled"}\n', file=f)

                self._format_policy_markdown(user, f)

                print("-" * 30, file=f)


    def format_group_markdown(self, groups: dict, filename: str) -> None:
        """Print out user details to markdown file - will overwrite existing file

        Args:
            users (dict): _description_
            filename (str): _description_
        """
        with open(filename, 'w') as f:
            print("# Groups \n", file=f)
            for groupname, group in groups.items():
                print(f'## group: {groupname} \n\n '
                      f'created: {group["CreateDate"]} \n '
                      f'### Users in group: \n'
                , file=f)
                print(tabulate.tabulate(group["users"], headers="keys", tablefmt="pipe"), file=f)

                self._format_policy_markdown(group, f)

                print("-" * 30, file=f)


if __name__ == '__main__':

    session = Utils.get_session()
    iam_client = session.client('iam')

    iam = IAM()
    users = iam.users(iam_client)
    iam.format_user_markdown(users, "./users.md")
    groups = iam.groups(iam_client)
    iam.format_group_markdown(groups, "./groups.md")
    
