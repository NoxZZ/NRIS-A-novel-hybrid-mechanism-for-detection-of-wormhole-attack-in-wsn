
#this function prints the neighbours of every single node present in the Wireless Sensor Network
def SanitizeRoutingTable():
    file = open("/home/noxz/BE_project/ns-allinone-3.30.1/ns-3.30.1/wormhole.routes")
    lines = file.readlines()
    req_lines = []
    neighborSet = dict()
    for line in lines:
        cols= line.split("\t")
        if len(cols) == 6:
            req_lines.append(cols)
    for x in req_lines:
        del x[3]
        del x[3] 
        x[3] = x[3].strip()
        temp_3 = []
        if((x[0] == x[1]) and (x[3] == '1') and (x[0] != x[2]) and (x[0]!= '10.0.1.255' and x[0] != '10.1.2.255') ): 
            temp_1 = x[2].split('.')
            temp_2 = x[0].split('.')
            if(temp_1[1] == '0' and temp_2[1] == '0'):
                if int(temp_1[3]) in neighborSet:
                    neighborSet[int(temp_1[3])].append(int(temp_2[3]))
                else:
                    neighborSet[int(temp_1[3])] = [int(temp_2[3])]
    print(neighborSet)
    return  (neighborSet)
