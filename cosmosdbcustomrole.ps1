Set-AzContext -Subscription "686af847-7b8d-47fa-88dd-b085fb0bb9d9"
Write-Host "Please select the option"
Write-Host "1: List custom Roles applied on Account"
Write-Host "2: Create Custom Roles for Write access"
Write-Host "3: Create Custom Roles for Read access"
Write-Host "4: Add users or groups to roles"
Write-Host " Root-level-scope use "/" "
Write-Host " Database-level-scope use "/dbs/database_name" "
Write-Host " Container-level-scope use "/dbs/database_name/colls/container_name" "

# Program starts from here
for ($i = 1; ; $i++) {
    $input = Read-Host "Enter your requirement"

    # Use a switch statement to process the input.
    switch ($input) {
        "1" {
            $AccountName = Read-Host -Prompt "Enter account name"
            $ResourceGroupName = Read-Host -Prompt "Enter resource group name"
            Get-AzCosmosDBSqlRoleDefinition -AccountName $AccountName -ResourceGroupName $ResourceGroupName
        }
        "2" {
            $subscription = Read-Host -Prompt "Enter subscription id"
            $accountName = Read-Host -Prompt "Enter account name"
            $resourceGroupName = Read-Host -Prompt "Enter resource group name"
            $scope = Read-Host -Prompt "Enter scope"
            $type = Read-Host -Prompt "Enter scope type"
            $targetresourceName = Read-Host -Prompt "Enter targetresourceName"
            Select-AzSubscription -SubscriptionId $subscription
            New-AzCosmosDBSqlRoleDefinition -AccountName $accountName `
                -ResourceGroupName $resourceGroupName `
                -Type CustomRole -RoleName "Custom-$targetresourceName-$type-Write-AccessRole" `
                -DataAction @( 
                    'Microsoft.DocumentDB/databaseAccounts/readMetadata',
                    'Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/items/create',
                    'Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/items/read',
                    'Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/items/replace',
                    'Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/items/upsert',
                    'Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/items/delete',
                    'Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/executeQuery',
                    'Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/readChangeFeed',
                    'Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/executeStoredProcedure',
                    'Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/manageConflicts'
                ) `
                -AssignableScope "$scope"
        }
        "3" {
            $subscription = Read-Host -Prompt "Enter subscription id"
            $accountName = Read-Host -Prompt "Enter account name"
            $resourceGroupName = Read-Host -Prompt "Enter resource group name"
            $scope = Read-Host -Prompt "Enter scope"
			$type = Read-Host -Prompt "Enter scope type"
            $targetresourceName = Read-Host -Prompt "Enter targetresourceName"
            Select-AzSubscription -SubscriptionId $subscription
            New-AzCosmosDBSqlRoleDefinition -AccountName $accountName `
                -ResourceGroupName $resourceGroupName `
                -Type CustomRole -RoleName "Custom-$targetresourceName-$type-Read-AccessRole" `
                -DataAction @( 
                    'Microsoft.DocumentDB/databaseAccounts/readMetadata',
                    'Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/items/read',
                    'Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/executeQuery',
                    'Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/readChangeFeed'
                    
                ) `
                -AssignableScope "$scope"
        }
        "4" {
            $subscription = Read-Host -Prompt "Enter subscription id"
            $accountName = Read-Host -Prompt "Enter account name"
            $resourceGroupName = Read-Host -Prompt "Enter resource group name"
            $scope = Read-Host -Prompt "Enter scope"
            $CustomRoleDefinitionId = Read-Host -Prompt "Enter CustomRoleDefinitionId"
            $principalId = Read-Host -Prompt "Enter principal Id"
            Select-AzSubscription -SubscriptionId $subscription
            New-AzCosmosDBSqlRoleAssignment -AccountName $accountName `
                -ResourceGroupName $resourceGroupName `
                -RoleDefinitionId $CustomRoleDefinitionId `
                -Scope "$scope" `
                -PrincipalId $principalId
        }
        default {
            Write-Host "You entered an invalid input."
        }
    }

    # Check if the user wants to continue.
    $continue = Read-Host "Do you want to continue? (Y/N)"
	if ($continue -ne "Y") {
        break
    }
	Write-Host "Please select the option"
    Write-Host "1: List custom Roles applied on Account"
    Write-Host "2: Create Custom Roles for Write access"
    Write-Host "3: Create Custom Roles for Read access"
    Write-Host "4: Add users or groups to roles"   
}
