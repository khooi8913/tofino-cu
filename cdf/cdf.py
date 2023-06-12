import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import numpy as np
import statistics as stats
off = []
non_off = []

with open("latency_offload.txt", "r") as filestream:
    for index, line in enumerate(filestream.readlines()):
        if(index != 0):
            try:
                # print(line)
                off.append(int(line.split()[0]))
            except:
                print("done")

filestream.close()
# print(len(tf1[]))
# tf1=tf1[:len(tf1)-1300]
print("median of offload case is", stats.median(off))
print ("\n")
p =np.percentile(np.array(off),99)
print("99 percentile of offload case is", p)
p =np.percentile(np.array(off),99.9)
print("99.9 percentile of offload case is", p)

# Read the data from CSV file
data = pd.read_csv('iperf-udp-cu.csv')

non_off = data['Difference'].head(12000)
non_off = non_off.sort_values()
non_off = non_off[:10000]
print("median of non-offload case is", stats.median(non_off)*1000)
p =np.percentile(np.array(non_off),99)
print("99 percentile of non-offload case (is", p*1000)
p =np.percentile(np.array(non_off),99.9)
print("99.9 percentile of non-offload case is", p*1000)

# non_off = non_off[1]
# print(non_off)
# sns.kdeplot(data = off, cumulative = True,label="Latency_offload")
sns.kdeplot(data = non_off, cumulative = True,label="Latency_CPU")

# Add labels and title to the plot
plt.xlabel('Latency(in ms)')
plt.ylabel('Density')

# plt.xscale('log')
# Show the plot
plt.legend()
plt.show()