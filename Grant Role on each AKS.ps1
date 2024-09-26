# Define the App ID
$appId = "4fb9b26a-9f46-4afb-a3fb-78f7056f7ecc"

# Define the subscription IDs you want to grant access to
$subscriptionIds = @("b638e83d-9274-4998-8bac-3a9f39dd7171", "0bbdfb4c-9e7c-4611-b6a7-33509d107c66", "bec8d1e4-c1cb-42b4-a341-fa12c6e3b86d")

# Loop through each subscription
foreach ($subscriptionId in $subscriptionIds) {
    # Set the current subscription
    Set-AzContext -SubscriptionId $subscriptionId

    # Get the list of AKS clusters in the current subscription
    $aksClusters = Get-AzAksCluster

    foreach ($aksCluster in $aksClusters) {
        # Grant the AKS Cluster Admin Role to the App ID
        $adminRoleAssignment = New-AzRoleAssignment -ApplicationId $appId -RoleDefinitionName "Azure Kubernetes Service Cluster Admin Role" -Scope $aksCluster.Id

        # Grant the AKS Cluster User Role to the App ID
        $userRoleAssignment = New-AzRoleAssignment -ApplicationId $appId -RoleDefinitionName "Azure Kubernetes Service Cluster User Role" -Scope $aksCluster.Id

        # Output the results (optional)
        Write-Host "Assigned AKS Cluster Admin Role to $appId in subscription $subscriptionId for cluster $($aksCluster.Name)."
        Write-Host "Assigned AKS Cluster User Role to $appId in subscription $subscriptionId for cluster $($aksCluster.Name)."
    }
}
