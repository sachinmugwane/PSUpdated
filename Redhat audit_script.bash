#!/bin/bash


DAYS=90
now=$(date +%s)
username=$(awk -F: '($3>=1000)&&($1!="nobody")&&($1!="packer")&&($1!="dcscaf")&&($1!="sisips"){print $1}' /etc/passwd)

for users in $username
do
        group=`groups $users | awk -F ':' '{print $2}'`
        comments=`cat /etc/passwd| grep "^$users:" | awk -F ':' '{print $5}'`
        sudoers=`sudo -l -U $users | grep -A20 "User $users" | sed 1d | sed 's/^ *//' | paste -sd',' `

        user_count=$(lastlog -u $users | sed 1d | grep -v "Never logged in" | wc -l)
        #user_count=$(last -FRn 1 -w $users | egrep -v "wtmp begins|still logged in" | grep ^$users | wc -l)
        if [ $user_count -gt 0 ]; then
                last_login=$(date -d "$(lastlog -u $users | sed 1d | awk '{print $(NF-4)" "$(NF-3)" "$(NF-2)" "$(NF-1)" "$NF}')" +%s)
                #last_login=$(date -d "$(last -FRn 1 -w $users| egrep -v "wtmp begins|still logged in" | grep ^$users| awk '{print $10 " " $11 " " $13 " " $12}')" +%s)
                last_login_days=$(( (now - last_login) / 86400 ))
                if [ $last_login_days -ge $DAYS ];then

                        users_login=$last_login_days
                else
                        users_login=$last_login_days

                fi
        else
                users_login=$( echo "Never Logged In")
        fi

        echo "$users;$comments;$group;$sudoers;$users_login"
done

