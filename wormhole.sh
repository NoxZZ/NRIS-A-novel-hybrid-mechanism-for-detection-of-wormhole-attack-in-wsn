#!/bin/bash
#gnome-terminal --working-directory=/home/noxz/BE_project/ns-allinone-3.30.1/ns-3.30.1  
counter=5
while [ $counter -le 50 ]
do
	cd /home/noxz/BE_project/ns-allinone-3.30.1/ns-3.30.1 && ./waf --run  " scratch/wormhole2 --AttackStat="true" --pcktCnt=$counter " >> /home/noxz/output.txt
	counter=$((counter += 5)) 
done	
