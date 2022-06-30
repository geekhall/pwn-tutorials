# -*- coding:utf8 -*-

import os
import boto3
import botocore


s3 = boto3.resource('s3')

for bucket in s3.buckets.all():
    print(bucket.name)
