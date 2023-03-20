import base64
import re
import boto3
import urllib3
import json
import logging
from botocore.signers import RequestSigner

# Constants
CLUSTER_NAME = 'eks-autoscaling'

def lambda_handler(event, context):
    # EKS / KubeApi Settting
    eks = boto3.client('eks')
    cluster = eks.describe_cluster(name=CLUSTER_NAME)['cluster']
    kubeApiServerEndpoint = cluster['endpoint']
    kubeApiKey = get_api_token(CLUSTER_NAME)
    httpClient = urllib3.PoolManager(cert_reqs='CERT_NONE')
    
    
    pods = get_pods(httpClient, kubeApiServerEndpoint, kubeApiKey)
    
        # Validation TODO check whether port number is opend in worker node security group?
    completed = False
    message = "Sorry, this task is not completed yet."
    progressPercent = 0

    if pods is not None:
        if pods['items'][0]['status']['phase'] == "Running":
            completed = True
            message = "Task Completed"
            progressPercent = 100
        else:
            message = "Pod in not running"
    else:
        message = "Pod is not found"

    return {
        "completed": completed, # required: whether this task is completed
        "message": message, # required: a message to display to the team indicating progress or next steps
        "progressPercent": progressPercent, # optional: any whole number between 0 and 100
        "metadata": {}, # optional: a map of key:value attributes to display to the team
    }

def get_api_token(clusterName):
    session = boto3.Session()
    client = session.client('sts')
    service_id = client.meta.service_model.service_id

    signer = RequestSigner(
        service_id,
        session.region_name,
        'sts',
        'v4',
        session.get_credentials(),
        session.events
    )

    params = {
        'method': 'GET',
        'url': 'https://sts.{}.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15'.format(session.region_name),
        'body': {},
        'headers': {
            'x-k8s-aws-id': clusterName
        },
        'context': {}
    }

    signed_url = signer.generate_presigned_url(
        params,
        region_name=session.region_name,
        expires_in=60,
        operation_name=''
    )

    base64_url = base64.urlsafe_b64encode(signed_url.encode('utf-8')).decode('utf-8')

    # remove any base64 encoding padding:
    return 'k8s-aws-v1.' + re.sub(r'=*', '', base64_url)

def get_pods(httpClient, kubeApiServerEndpoint, kubeApiKey):
    res = httpClient.request('GET', kubeApiServerEndpoint + '/api/v1/namespaces/karpenter/pods', headers={"authorization" : "Bearer " + kubeApiKey})
    if res.status == 200:
        pods = json.loads(res.data.decode('utf-8'))
    else:
        logging.error('Get Pods Failed', exc_info=True)
        pods = None

    return pods