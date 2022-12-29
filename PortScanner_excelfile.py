#Zyquier Brownridge
# IP PORT SCANNER THAT PUT OPEN/CLOSE PORTS INTO EXCEL FILE and THOSE RELATED SERVICES

import nmap
import pandas as pd


target = ''
scanner = nmap.PortScanner()

portnum = []   # data list for data frames
oc = []
portname = []

print('NetworkScanner')
print('ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ')
sos = input('Enter Begnning Port') #Start of scan
ep = input('Enter Last Port')

begin = int(sos)
end = int(ep)

def isyou_up():   #portopen
   for i in range(begin, end+1):
    res = scanner.scan(target, str(i))
    res = res['scan'][target]['tcp'][i]['state']
    portnum.append(i)
    oc.append(res)


def name():
   for i in range(begin, end+1):
    res = scanner.scan(target, str(i))
    name = res['scan'][target]['tcp'][i]['name']
    portname.append(name)




def see():
 frame = {'Port#':portnum,'State':oc,'Service':portname}
 df = pd.DataFrame(frame)
 df.to_excel('Dy.xlsx')
 print("NetworkScanResults for IP:"+target)
 print(df)


isyou_up()
name()
see()






