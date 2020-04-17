'''
    This is the stage 3 for wormhole attack detection
    code authors-- 1. N0xZ
                   2. AJ
'''

import matplotlib.pyplot as plt
import pandas as pd
import csv
import os
import itertools
from routingTable import SanitizeRoutingTable
from stage1 import findSuspiciousNodes
from decimal import Decimal


#GRAPH PRINTING FUNCTION FOR ANALYSING THE NETWORK WITH AND WITHOUT ATTACK------->
def printWholeGraph():
    x = []
    y1 = []
    y2 = []
    y3 = []
    y4 = []
    y5 = []
    y6 = []
    cnt = 0
#NETWORKDATA.CSV IS GENERATED IN STAGE 2
    with open('networkdata.csv','r') as csvfile:
        plots = csv.reader(csvfile, delimiter='\t')
        for row in plots:
            row = row[0].split(',')
            if(cnt>0):
                x.append(int(row[0]))
                y1.append(float(row[1]))
                y2.append(float(row[4]))
                y3.append(float(row[2]))
                y4.append(float(row[5]))
                y5.append(float(row[3]))
                y6.append(float(row[6]))
            cnt+=1
    plot_graph(x,y1,y2,y3,y4,y5,y6)

#HELPING FUNCTION FOR PRINTING GRAPH 
def plot_graph(x,y1,y2,y3,y4,y5,y6):
    plt.subplot(231)        
    plt.plot(x,y1, label='without attack')
    plt.plot(x,y2, label=' with attack')
    plt.xlabel('No of packets')
    plt.ylabel('Avg throughput')
    plt.title('Average Throughput')
    plt.legend()
    plt.subplot(233)
    # packets = data.column.strip()
    plt.plot(x,y3, label='without attack')
    plt.plot(x,y4, label='with attack')
    plt.xlabel('No of packets')
    plt.ylabel('PDR(%)')
    plt.title('Packet delivery ratio(PDR) in %')
    plt.legend()
    # plt.show()
    plt.subplot(235)
    plt.plot(x,y5, label='without attack')
    plt.plot(x,y6, label='with attack')
    plt.xlabel('No of packets')
    plt.ylabel('avg. E2E delay')
    plt.title('End-to-End delay')
    plt.legend()
    plt.show()
    #CHECK ATTACK PRESENCE RETURNS TRUE IF NETWORK SHOWS MALICIOUS BEHAVIOUR
    val = checkAttackPresence(y1,y2,y3,y4,y5,y6)
    
    #IF STAGE 2 RETURNS TRUE.... STAGE 3 STARTS FROM HERE...
    if(val==True):
        #Suspicious_node_set = [2,3,5,6]
        #print("Entering stage 3")
        Suspicious_node_set = findSuspiciousNodes(SanitizeRoutingTable())
        tups = list(itertools.combinations(Suspicious_node_set,2))
        fin_list = []
        suspNodefin=[]
        for elem in tups:
            cmd = 'cd /home/noxz/BE_project/ns-allinone-3.30.1/ns-3.30.1 && ./waf --run "scratch/wormhole4 --SuspNode1='+str(elem[0])+' --SuspNode2='+str(elem[1])+' --pcktCnt='+str(x[0])+'"'
            outputBeforeAttack = os.popen(cmd).readlines()
            cmd = 'cd /home/noxz/BE_project/ns-allinone-3.30.1/ns-3.30.1 && ./waf --run "scratch/wormhole4 --SuspNode1='+str(elem[0])+' --SuspNode2='+str(elem[1])+' --pcktCnt='+str(x[0])+' --AttackStat=true"'
            outputAfterAttack = os.popen(cmd).readlines()
            if(checkWormholeLink(outputBeforeAttack[-1], outputAfterAttack[-1])!=None):
                suspNodefin.append(elem)
                fin_list.append(checkWormholeLink(outputBeforeAttack[-1], outputAfterAttack[-1]))
        #print('the final list is --',fin_list)
        #print('the susp node fin is --',suspNodefin)
        finalCheck(fin_list,suspNodefin,Suspicious_node_set)


#FUNCTION DEFINITION FOR CHECKING THE ATTACK PRESENT IN THE NETWORK
def checkAttackPresence(y1,y2,y3,y4,y5,y6):
    mean_y1 = sum(y1)/len(y1)
    mean_y2 = sum(y2)/len(y2)
    mean_y3 = sum(y3)/len(y3)
    mean_y4 = sum(y4)/len(y4)
    mean_y5 = sum(y5)/len(y5)
    mean_y6 = sum(y6)/len(y6)
    diff1 = abs(mean_y2-mean_y1)
    diff2 = abs(mean_y3-mean_y4)
    diff3 = abs(mean_y5-mean_y6)
    c = len(y1)
    attack_prob1 = 0
    attack_prob2 = 0
    attack_prob3 = 0
    print(y3,y4)
    for e in range(0,len(y1)):
        if(float(y1[e]) > float(y2[e])):
            attack_prob1+=1
        if(float(y3[e]) > float(y4[e])):
            attack_prob2+=1
        if(float(y5[e]) < float(y6[e])):
            attack_prob3+=1
    print(attack_prob1,attack_prob2,attack_prob3)
    avg = (attack_prob1+attack_prob2+attack_prob3)/3
    print(diff1,diff2,diff3)
    #print(avg,c)
    if(avg>=c/2):
        return(True)

#FUNCTION FOR CHECKING ALTERNATE POSSIBLE LINK 
def checkWormholeLink(output1, output2):
        list1 = output1.split('\t')
        list2 = output2.split('\t')
        list1[-1] = list1[-1][:-1]
        list2[-1] = list2[-1][:-1]
        list1 = [float(i) for i in list1]
        list2 = [float(i) for i in list2]
        dif1 = abs(list1[0]-list2[0])
        dif2 = abs(list1[1]-list2[1])
        dif3 = abs(list1[2]-list2[2])
        if(list1[1]==0.0 and list1[2]==0.0):
            print('Error : no alternate link between source and destination found..')
            print(list1,list2)    
        else:
            print('Alternate link found successfully! parameters info ---',list1,list2)
            return([dif1,dif2,dif3])
#FUNCTION FOR CHECKING MALICIOUS LINK BETWEEN FINAL NODE PAIR
def finalCheck(a,b,c):
    temp1=[]
    temp2=[]
    temp3=[]
    temp4=[]
    for e in a:
        temp1.append(e[0])
        temp2.append(e[1])
        temp3.append(e[2])
    print(temp1,temp2,temp3)
    val1 = temp1.index(max(temp1))
    val2 = temp2.index(max(temp2))
    val3 = temp3.index(max(temp3))
    print(val1,val2,val3)
    if(val1==val3):
        temp4 = [x for x in c if x not in b[val1]]
    else:
        print('working on this condition')
    print('Final suspicious node set ---->',temp4)


printWholeGraph()

