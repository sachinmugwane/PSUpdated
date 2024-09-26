# Get a list of all subscriptions
$subscriptions = Get-AzSubscription

# Initialize an array to store AKS cluster details
$aksClusterDetails = @()

# Loop through each subscription
foreach ($subscription in $subscriptions) {
    # Set the current subscription
    Set-AzContext -Subscription $subscription

    # Get AKS clusters in the current subscription
    $aksClusters = Get-AzAksCluster

    # Loop through each AKS cluster
    foreach ($aksCluster in $aksClusters) {
        # Get the location of the current cluster
        $location = $aksCluster.Location
        $KubernetesVersion = $aksCluster.KubernetesVersion

        # Get node pool details for the current cluster
        $nodePools = Get-AzAksNodePool -ResourceGroupName $aksCluster.ResourceGroupName -ClusterName $aksCluster.Name

        # Loop through each node pool
        foreach ($nodePool in $nodePools) {
            $aksClusterDetail = [PSCustomObject]@{
                'Cluster Name' = $aksCluster.Name
                'Subscription Name' = $subscription.Name
                'Resource Group' = $aksCluster.ResourceGroupName
                'Location' = $location
                'Kubernetes Version' = $KubernetesVersion
                'NodePool Name' = $nodePool.Name
                'NodePool Mode' = $nodePool.Mode
                'NodePool Disk Type' = $nodePool.OsDiskType
                'NodePool Size' = $nodePool.VmSize
                'Min Nodes' = $nodePool.MinCount
                'Max Nodes' = $nodePool.MaxCount
                'Max Pods Per Node' = $nodePool.MaxPods
		        'Node Count' = $nodePool.count
                'NodePool Vnet' = $nodePools.VnetSubnetID.Split("/")[-3]
                'NodePool Subnet' = $nodePools.VnetSubnetID.Split("/")[-1]
                'autoscaling' = $nodePool.enableAutoScaling
                'Max Surge' = $nodePool.upgradesettings.maxSurge
                'UptimeSLA' = $aksCluster.Sku.Tier
                'CSI Driver' = $aksCluster.StorageProfile.FileCSIDriver.Enabled

            }

            # Add the AKS cluster detail to the array
            $aksClusterDetails += $aksClusterDetail
        }
    }
}

# Output the AKS cluster details
$aksClusterDetails |  Export-Csv -Path D:\AllAKS.csv -NoTypeInformation
