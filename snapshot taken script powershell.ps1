# Taking number for patch day 
Param (
    
    [Parameter(Mandatory = $true)]
    [String] $Patchday
)

# This should be the local path of  patching excel file
$csvPath = "C:\Users\aniket.salunke\Desktop\Patchingsnapshots.xlsx"

#enter Subscription ID of VMs

Set-AzContext -Subscription "ASB-SIS-DR"

$vmfrportal = Get-AzVM

#Taking names of VM to be patched Today
$vms = Import-Excel $csvPath | Select-Object -ExpandProperty NAME

#Use this If file is in.csv format - $vms = Import-Csv $csvPath | Select-Object -ExpandProperty NAME
 
$vm002 = $vmfrportal 

$snapshotCount = 0

foreach ($vm in $vm002) {


#comparing the excel sheet VM Name coloum with foreach loop VM 
if ($vms -eq $vm.name){

    #taking name of VM
    $vmname = $vm.Name
   
   #taking RG of VM
    $resourceGroupName = $vm.ResourceGroupName

    #Taking OD disk ID of VM
    $osDiskId = $vm.StorageProfile.OsDisk.ManagedDisk.Id

    #taking Tags of OS disk
    $osDiskTags = (Get-AzDisk -ResourceGroupName $resourceGroupName -DiskName $vm.StorageProfile.OsDisk.Name).Tags
    
     #Taking OD disk ID of VM
    $dataDiskId = $vm.StorageProfile.data_Disk.ManagedDisk.Id

    #taking Tags of Data disk
    $dataDiskTags = (Get-AzDisk -ResourceGroupName $resourceGroupName -DiskName $vm.StorageProfile.data_Disk.Name).Tags

    #setup snapshot configration [ by defualt Standard HDD LRS]
    $snapshotConfig = New-AzSnapshotConfig -SourceResourceId $osDiskId -Location eastus -CreateOption Copy -Tag $osDiskTags
    
    #setup snapshot configration [ by defualt Standard HDD LRS]
    $snapshotConfig = New-AzSnapshotConfig -SourceResourceId $dataDiskId -Location eastus -CreateOption Copy -Tag $dataDiskTags
    
    #setup name format of snapshot example [ Patchday03-linux-b2cbre-prd-web1-2023-09-11 ]
    $snapshotName = "$vmName-OSDisk-Windows-Patching-$patchday-$(Get-Date -Format yyyy-MM-dd)"
    
    #setup name format of snapshot example [ Patchday03-linux-b2cbre-prd-web1-2023-09-11 ]
    $snapshotName = "$vmName-DataDisk-Windows-Patching-$patchday-$(Get-Date -Format yyyy-MM-dd)"

    #creating snapshot
    $snapshot = New-AzSnapshot  -ResourceGroupName $resourceGroupName -SnapshotName $snapshotName -Snapshot $snapshotConfig

    #for output at PS window
    $Nameofsnapshot = Update-AzSnapshot -Snapshot $snapshot -ResourceGroupName $resourceGroupName -SnapshotName $snapshotName 

     $shownames = $vmname+"---Spanshotname--->>>"+ $Nameofsnapshot.Name

    $shownames

    $snapshotCount++


    }
    }

    Write-Host "Total number of snapshots created: $snapshotCount"

