####################
##  Tools Install ##
####################

mkdir -p workspace && cd workspace

# reset yum history
sudo yum history new

# Install jq (json query)
sudo yum -y -q install jq

# Install yq (yaml query)
echo 'yq() {
  docker run --rm -i -v "${PWD}":/workdir mikefarah/yq "$@"
}' | tee -a ~/.bash_profile && source ~/.bash_profile

# Install other utils:
#   gettext: a framework to help other GNU packages product multi-language support. Part of GNU Translation Project.
#   bash-completion: supports command name auto-completion for supported commands
#   moreutils: a growing collection of the unix tools that nobody thought to write long ago when unix was young
sudo yum -y install gettext bash-completion moreutils

# Update awscli v1, just in case it's required
pip install --user --upgrade awscli

# Install awscli v2
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install
rm awscliv2.zip


######################
##  Set Variables  ##
#####################

# Set AWS LB Controller version
echo 'export LBC_VERSION="v2.4.1"' >>  ~/.bash_profile
echo 'export LBC_CHART_VERSION="1.4.1"' >>  ~/.bash_profile
.  ~/.bash_profile

# Set AWS region in env and awscli config
AWS_REGION=$(curl --silent http://169.254.169.254/latest/dynamic/instance-identity/document | jq -r .region)
echo "export AWS_REGION=${AWS_REGION}" | tee -a ~/.bash_profile
echo "export AWS_DEFAULT_REGION=${AWS_REGION}" | tee -a ~/.bash_profile

# Set accountID
ACCOUNT_ID=$(aws sts get-caller-identity --output text --query Account)
echo "export ACCOUNT_ID=${ACCOUNT_ID}" | tee -a ~/.bash_profile

# Set EKS cluster name
EKS_CLUSTER_NAME=$(aws eks list-clusters --region ${AWS_REGION} --query clusters --output text)
echo "export EKS_CLUSTER_NAME=${EKS_CLUSTER_NAME}" | tee -a ~/.bash_profile
echo "export CLUSTER_NAME=${EKS_CLUSTER_NAME}" | tee -a ~/.bash_profile


# Configure Cloud9 creds
aws cloud9 update-environment --region ${AWS_REGION} --environment-id $C9_PID --managed-credentials-action DISABLE

# Install kubectl
#  enable desired version by uncommenting the desired version below:
#   kubectl version 1.19
#   curl -o kubectl https://amazon-eks.s3.us-west-2.amazonaws.com/1.19.6/2021-01-05/bin/linux/amd64/kubectl
#   kubectl version 1.20
#   curl -o kubectl https://amazon-eks.s3.us-west-2.amazonaws.com/1.20.4/2021-04-12/bin/linux/amd64/kubectl
#   kubectl v1.21
#   curl -o kubectl https://amazon-eks.s3.us-west-2.amazonaws.com/1.21.2/2021-07-05/bin/linux/amd64/kubectl
#   kubectl v1.22
#   curl -O https://s3.us-west-2.amazonaws.com/amazon-eks/1.22.17/2023-01-30/bin/linux/amd64/kubectl
#   kubectl v1.23
#   curl -O https://s3.us-west-2.amazonaws.com/amazon-eks/1.23.16/2023-01-30/bin/linux/amd64/kubectl
#   Kubectl v1.24
#   curl -O https://s3.us-west-2.amazonaws.com/amazon-eks/1.24.10/2023-01-30/bin/linux/amd64/kubectl
curl -o /tmp/kubectl https://s3.us-west-2.amazonaws.com/amazon-eks/1.24.10/2023-01-30/bin/linux/amd64/kubectl
sudo chmod +x /tmp/kubectl
sudo mv /tmp/kubectl /usr/local/bin


# set kubectl as executable, move to path, populate kubectl bash-completion
echo "source <(kubectl completion bash)" >> ~/.bash_profile
echo "source <(kubectl completion bash | sed 's/kubectl/k/g')" >> ~/.bash_profile

# Install c9 for editing files in cloud9
npm install -g c9

# Install eksctl and move to path
curl --silent --location "https://github.com/weaveworks/eksctl/releases/latest/download/eksctl_$(uname -s)_amd64.tar.gz" | tar xz -C /tmp
sudo mv /tmp/eksctl /usr/local/bin

# Install helm
curl -sSL https://raw.githubusercontent.com/helm/helm/master/scripts/get-helm-3 | bash

# Install k9s
curl -Lo k9s.tgz https://github.com/derailed/k9s/releases/download/v0.27.3/k9s_Linux_amd64.tar.gz
tar -xf k9s.tgz
sudo install k9s /usr/local/bin/

# Install aliases
echo "alias k='kubectl'" | tee -a ~/.bash_profile
echo "alias kgp='kubectl get pods'" | tee -a ~/.bash_profile
echo "alias kgsvc='kubectl get svc'" | tee -a ~/.bash_profile
echo "alias kgn='kubectl get nodes -L beta.kubernetes.io/arch -L eks.amazonaws.com/capacityType -L beta.kubernetes.io/instance-type -L eks.amazonaws.com/nodegroup -L topology.kubernetes.io/zone -L karpenter.sh/provisioner-name -L karpenter.sh/capacity-type'" | tee -a ~/.bash_profile

# Clone lab repositories
#cd ~/environment
#git clone https://github.com/brentley/ecsdemo-frontend.git
#git clone https://github.com/brentley/ecsdemo-nodejs.git
#git clone https://github.com/brentley/ecsdemo-crystal.git
#git clone https://github.com/aws-containers/eks-app-mesh-polyglot-demo.git

# Update kubeconfig and set cluster-related variables if an EKS cluster exists

if [[ "${EKS_CLUSTER_NAME}" != "" ]]
then

# Update kube config
    aws eks update-kubeconfig --name ${EKS_CLUSTER_NAME} --region ${AWS_REGION}

# Set EKS node group name
    EKS_NODEGROUP=$(aws eks list-nodegroups --cluster ${EKS_CLUSTER_NAME} --region ${AWS_REGION} | jq -r '.nodegroups[0]')
    echo "export EKS_NODEGROUP=${EKS_NODEGROUP}" | tee -a ~/.bash_profile

# Set EKS nodegroup worker node instance profile
    ROLE_NAME=$(aws eks describe-nodegroup --cluster-name $EKS_CLUSTER_NAME --nodegroup-name ${EKS_NODEGROUP} --region ${AWS_REGION} --query 'nodegroup.nodeRole' --output text)
    echo "export ROLE_NAME=${ROLE_NAME}" | tee -a ~/.bash_profile

elif [[ "${EKS_CLUSTER_NAME}" = "" ]]
then

# Print a message if there's no EKS cluster
   echo "There are no EKS clusters provisioned in region: ${AWS_REGION}"

fi

# Print a message if there's no worker node instance profile set

if [[ "${ROLE_NAME}" = "" ]]
then

   echo "!!WARNING - Please set an EC2 instance profile for your worker nodes in the ${EKS_CLUSTER_NAME} cluster"

fi

# Update aws-auth ConfigMap granting cluster-admin to TeamRole (cluster creator is "eksworkshop-admin")
eksctl create iamidentitymapping \
  --cluster ${EKS_CLUSTER_NAME} \
  --arn arn:aws:iam::${ACCOUNT_ID}:role/TeamRole \
  --username cluster-admin \
  --group system:masters \
  --region ${AWS_REGION}


# Helm Install
curl -sSL https://raw.githubusercontent.com/helm/helm/master/scripts/get-helm-3 | bash
helm version --short
helm repo add stable https://charts.helm.sh/stable

# helm bash-completion
helm completion bash >> ~/.bash_completion
. /etc/profile.d/bash_completion.sh
. ~/.bash_completion
source <(helm completion bash)

# helm update
helm repo add karpenter https://charts.karpenter.sh/
helm repo update


# cleanup
rm -vf ${HOME}/.aws/credentials

