# Set the Azure context
Set-AzContext -Subscription "686af847-7b8d-47fa-88dd-b085fb0bb9d9"

# Initialize an empty array to store the results
$results = @()

# Get all resource groups in the subscription
$resourceGroups = Get-AzResourceGroup

foreach ($resourceGroup in $resourceGroups) {
    $resourceGroupName = $resourceGroup.ResourceGroupName

    # Get all Cosmos DB accounts in the current resource group
    $cosmosAccounts = Get-AzCosmosDBAccount -ResourceGroupName $resourceGroupName

    foreach ($account in $cosmosAccounts) {
        $accountName = $account.Name

        # Get the custom roles in the current Cosmos DB account
        $customRoles = Get-AzCosmosDBSqlRoleDefinition -AccountName $accountName -ResourceGroupName $resourceGroupName

        # Get all role assignments in the current Cosmos DB account
        $roleAssignments = Get-AzCosmosDBSqlRoleAssignment -AccountName $accountName -ResourceGroupName $resourceGroupName

        # Iterate through each role assignment
        foreach ($assignment in $roleAssignments) {
            $principalId = $assignment.PrincipalId
            $displayName = ""

            # Check if principal ID is a user, service principal, or group
            $user = Get-AzADUser -ObjectId $principalId -ErrorAction SilentlyContinue
            $servicePrincipal = Get-AzADServicePrincipal -ObjectId $principalId -ErrorAction SilentlyContinue
            $group = Get-AzADGroup -ObjectId $principalId -ErrorAction SilentlyContinue

            if ($user) {
                $displayName = $user.DisplayName
            } elseif ($servicePrincipal) {
                $displayName = $servicePrincipal.DisplayName
            } elseif ($group) {
                $displayName = $group.DisplayName
            }

            # Find the corresponding role definition
            $role = $customRoles | Where-Object { $_.Id -eq $assignment.RoleDefinitionId }

            $results += [PSCustomObject]@{
                AssignmentID = $assignment.Id
                Scope = $assignment.Scope
                RoleDefinitionId = $assignment.RoleDefinitionId
                PrincipalId = $principalId
                DisplayName = $displayName
                RoleName = $role.RoleName
                CosmosDBAccountName = $accountName
            }
        }
    }
}

# Export the results to CSV
$results | Export-Csv -Path D:\Report\AllCosmosDB-Combined.csv -NoTypeInformation
