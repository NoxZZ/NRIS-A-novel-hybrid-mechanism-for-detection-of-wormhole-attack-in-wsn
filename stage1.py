'''
    This is the stage 1 for wormhole attack detection
    code authors-- 1. N0xZ
                   2. AJ
'''

import itertools
from routingTable import SanitizeRoutingTable
import time
from performanceMetrics import performanceMetricsCalculation 
#function derived from base paper for determining the supicious node set----------
def findSuspiciousNodes(neighborSet):
    S = []  # Suspicious Node Set
    R = 1.1  # Manually set to 1.1 taking in account the normal range

    # neighborSet = {1: [2, 3], 2: [1, 3, 5], 3: [1, 2, 5], 4: [2, 5, 6], 5: [1, 3, 6], 6: [2, 4, 5]}
    neighborRatioForEachNode = []

    for i in range(len(neighborSet)):
        # \Ni\
        Ni = len(neighborSet[i + 1])

        s = 0
        for j in range(Ni):
            Nj = len(neighborSet[(neighborSet[i + 1][j])])
            # print(Nj, end=' ')
            s = s + Nj
        # print(s)
        NiAvg = s / Ni
        Ri = Ni / NiAvg
        neighborRatioForEachNode.append(Ri)
        if Ri > R:
            S.append(i + 1)
    print("Suspicious Node Set: ", S)
    return(S)


findSuspiciousNodes(SanitizeRoutingTable())

