import numpy as np,json
import matplotlib.pyplot as plt

ServerIDs = [2,3,4]
x,lowdata,mediandata,highdata = [],[],[],[] 
for ServerID in ServerIDs:
    with open(f'NessAPI/scanHost_{ServerID}_Detail.json','r') as f:
        Server = json.load(f)
        x.append(Server['info']['host-ip'])
        lowcount,mediancount,highcount = 0,0,0
        for i in Server['vulnerabilities']:
            if i['severity'] == 0 :
                lowcount += i['count']
            elif i['severity'] == 1 :
                mediancount += i['count']
            elif i['severity'] == 2 :
                highcount+= i['count']
        lowdata.append(lowcount)
        mediandata.append(mediancount)
        highdata.append(highcount)

plt.bar(x,lowdata,color='b',label= 'low',width=0.7,align='edge')  # 第一組數據靠左邊緣對齊
plt.bar(x,mediandata,color='g',label = 'median',width=0.6,align='edge' )# 第二組數據置中對齊
plt.bar(x,highdata,color='r',label='high' ,width=0.5,align='edge')
plt.legend(title='Mark')
plt.show()


def GeneratePIE() -> None:
    '''Pie Graph'''
    # ypoints = np.array([10,15,30,24,11])
    ypoints = [10,15,30,24,11]
    Labels = ['type1','type2','type3','type4','type5']
    plt.pie(ypoints,labels=Labels)
    plt.show()

def GenerateBarChat() -> None:
    '''Bar Chat'''
    # ypoints = np.array([0, 100,50])
    ypoints = [0, 100,50]
    # xpoints = np.array(['1','2','3'])
    xpoints = ['1','2','3']
    plt.bar(x=xpoints,height=ypoints)
    plt.show()

def GenerateLineChat() -> None:
    '''Line Chat'''
    # ypoints = np.array([0, 100,50])
    ypoints = [0, 100,50]
    # xpoints = np.array(['1','2','3'])
    xpoints = ['1','2','3']
    plt.plot(xpoints,ypoints)
    plt.show()

# GeneratePIE()
# GenerateBarChat()
# GenerateLineChat()
