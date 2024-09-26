# Get a list of all subscriptions
$subscriptions = Get-AzSubscription
 
# Initialize an array to store AKS cluster details
$aksClusterDetails = @()
 
# Loop through each subscription
foreach ($subscriptionId in $subscriptions) {
    # Set the current subscription
    Set-AzContext -Subscription $subscriptionId
 
    # Get AKS clusters in the current subscription
    $aksClusters = Get-AzAksCluster
 
    # Loop through each AKS cluster
    foreach ($aksCluster in $aksClusters) {
        # Get AKS IAM details
        $aksIAMDetails = Get-AzRoleAssignment -Scope $aksCluster.Id
 
        # Loop through each IAM detail for the AKS cluster
        foreach ($iamDetail in $aksIAMDetails) {
            $displayName = $iamDetail.DisplayName
            $email = $iamDetail.SignInName
            $role = $iamDetail.RoleDefinitionName
            $type = $iamDetail.ObjectType
            $scope = $iamDetail.Scope
 
            # Create an inner array for each AKS cluster and IAM detail
            $aksClusterDetail = @{
                "ClusterName" = $aksCluster.Name
                "DisplayName" = $displayName
                "Email" = $email
                "Role" = $role
                "Type" = $type
                "Scope" = $scope
            }
 
            # Add the inner array to $aksClusterDetails
            $aksClusterDetails += New-Object PSObject -Property $aksClusterDetail
        }
    }
}
 
# Output the AKS cluster details to CSV
$aksClusterDetails | Export-Csv -Path "D:\AllAKS.csv" -NoTypeInformation

