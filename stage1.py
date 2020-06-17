'''
    This is the stage 2 for wormhole attack detection
    code authors-- 1. N0xZ
                   2. AJ
'''

import csv
resultFile = "networkdata.csv"
rows1=[]
rows2=[]

with open("resultsBeforeAttack.csv", 'r') as csvfile1:
    csvreader1 = csv.reader(csvfile1)
    for row in csvreader1:
        rows1.append(row)
for i in range(len(rows1)):
    rows1[i] = rows1[i][0].split('\t')


#
with open("resultsAfterAttack.csv", 'r') as csvfile2:
    csvreader2 = csv.reader(csvfile2)
    for row in csvreader2:
        rows2.append(row)
#   print(rows2)

for i in range(len(rows2)):
    rows2[i] = rows2[i][0].split('\t')
# print(rows2)


#   Defining field names for result file...
resultFileFields = []
resultFileFields.extend(['Packets', 'Initial Average Throughput (in Kbps)', 'Initial Packet Delivery Ratio (in %)', 'Initial Average E2E Delay (in ms)','Final Average Throughput (in Kbps)','Final Packet Delivery Ratio (in %)',  'Final Average E2E Delay (in ms)'])
# print(resultFileFields)
print()


# data rows of result file...
result = []
resultpart1 = []
resultpart2 = []
resultRow1 = []

print("Part 1: ")

#   generating first half of each result
for l in range(1, len(rows1[0])):
    for k in range(len(rows1)):
        part1 = [rows1[k][l]]
        resultRow1.extend(part1)
    print(resultRow1)
    resultpart1.append(resultRow1)
    resultRow1 = []

print()
print("Part 2: ")

#   generating second half of each result
for l in range(1, len(rows2[0])):
    for k in range(1, len(rows2)):
        part1 = [rows2[k][l]]
        resultRow1.extend(part1)
    print(resultRow1)
    resultpart2.append(resultRow1)
    resultRow1 = []


#   print(resultpart1)
#   print(resultpart2)

#   Combining the two parts to generate final result.
for i in range(len(resultpart1)):
    result.append(resultpart1[i])
    result[i].extend(resultpart2[i])

print()
print("FINAL RESULT: ")
for i in range (len(result)):
    print(result[i])

with open(resultFile, 'w') as csvfile3:
    csvwriter = csv.writer(csvfile3)
    csvwriter.writerow(resultFileFields)
    for i in range(len(result)):
        csvwriter.writerow(result[i])
print("RESULT FILE CREATED!!")
    