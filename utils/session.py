import argparse
import boto3
import sys


class Utils:
    @staticmethod
    def get_session():
        # parser = argparse.ArgumentParser()
        # parser.add_argument(
        #     '--profile',
        #     help='AWS profile from ~/.aws/credentials',
        #     required=False,
        #     default='default'
        # )
        
        # args = parser.parse_args()

        try:
            session = boto3.Session(profile_name='tn_audit')
        except Exception as e:
            print('%s' % e)
            sys.exit(1)

        return session
    
    @staticmethod
    def paginate(service, method, list_key, **kwargs):
        paginator = service.get_paginator(method)
        for response in paginator.paginate(**kwargs):
            if list_key in response:
                yield from response[list_key]