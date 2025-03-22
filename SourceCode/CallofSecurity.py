
import os
import os.path
import pandas as pd
import gpiod
import time
import subprocess
from inputimeout import inputimeout
import sympy
import numpy as np
import matplotlib.pyplot as plt
import random
from mac_vendor_lookup import MacLookup
import maskpass as mp


plt.rcParams["figure.figsize"] = (18,18)

pd.set_option('display.max_columns', None) #allow max cols to display
#pd.set_option('diplay.max_rows',None) 
pd.set_option("expand_frame_repr",False)
global df
global trig_line
#For identity want deeper analysis 

def login():
	username = input("Enter Username: ")
	pwd= mp.askpass(mask="*",prompt="Enter Password: ")
	return username == "master" and pwd =="callofsec243#1"
	return

def rssi(val):
    
	#return 10**((27.55-(20*math.log(2400,10))+val)/20)
	# from EQ: RSSI= -(10n*log10*d+A)
	return 10**((val-(-50))/(-30)) # -50 rssi value for 1m / -30 path loss exponential
def calcLoc(xy):
	x, y = sympy.symbols("x y", real=True)
	eq4 = sympy.Eq((x-2)**2 - x**2 + (y-3)**2 -y**2,rssi(xy[1])**2 - rssi(xy[0])**2)
	eq5 = sympy.Eq((x-3.5)**2 - (x-2)**2 + (y)**2 -(y-3.5)**2,rssi(xy[2])**2 - rssi(xy[1])**2)	
	return sympy.solve([eq4,eq5])
def setuppins():
	global trig_line
	trig_pin=26
	chip = gpiod.Chip('gpiochip4')
	trig_line=chip.get_line(trig_pin)
	trig_line.request(consumer="trig", type=gpiod.LINE_REQ_DIR_OUT)
	trig_line.set_value(1)		

def PresenceNmap():
	mac = MacLookup()
	#Presence/Identity
	output = subprocess.check_output(["hostname -I"], shell=True)
	s=output.decode("utf8").strip()
	st2="sudo nmap -sn "+s+"/24 > output.txt"
	os.system(st2) # to check devices connected to router
	f=open("output.txt","r")
	f.readline()
	dicti={"Name": [],"MAC Address":[],"Manufacturer":[],"IP Address":[]}
	output = subprocess.check_output(["hostname -I"], shell=True)
	s=output.decode("utf8").strip()
	dicti["Name"].append("Ali")
	dicti["MAC Address"].append("2C:CF:67:0B:79:A9")
	dicti["Manufacturer"].append("Raspberry Pi")
	dicti["IP Address"].append(s)
	for x in f:
		if "Nmap scan report" in str(x):
			#print(x.split()[4])
			b=x.split()[4]
			if(len(x.split())>5):
				d=x.split()[5]
				d=d[1:-1]
			else:
				d=b
				b="Unknown"
		if "MAC Address" in str(x):
			#print(x[13:30])
			a=x[13:30]
			c=' '.join(map(str,x.split()[3:]))
			#print(c)
			dicti["Name"].append(b)
			dicti["MAC Address"].append(a)
			if(c!="(Unknown)"):
				dicti["Manufacturer"].append(c[1:-1])
				#print(c+" Hello")
			else:
				try:
					mac.update_vendors()
					dicti["Manufacturer"].append(mac.lookup(a))
					#print(c)
				except:
					dicti["Manufacturer"].append(c[1:-1])	
					#print("help")
			dicti["IP Address"].append(d)
	#print(dicti)		
	df=pd.DataFrame(dicti)
	df.set_index(df["MAC Address"], inplace=True, drop=True)
	df.drop("MAC Address", axis=1, inplace=True)	
	df.to_csv("test.csv")
def masterdataframesetup():
	global df
	if os.path.isfile("master.csv"): #checks if master file has been created containing all devices that have already been detected
		df=pd.read_csv("master.csv") #becomes main dataframe
		df.set_index(df["MAC Address"], inplace=True, drop=True) #makes mac the identifier instead of the index
		df.drop("MAC Address", axis=1, inplace=True)
		df=df.astype({"RFID Tag":str}) #IMPORTANT
		dfappend=pd.read_csv("test.csv") #newly scanned devices
		dfappend.set_index(dfappend["MAC Address"], inplace=True, drop=True)
		dfappend.drop("MAC Address", axis=1, inplace=True)
		for x in dfappend.index: #appends new devices to original dataframe
			#print(x)
			if not x in df.index:
				df.loc[x]=[dfappend.loc[x,"Name"],dfappend.loc[x,"Manufacturer"],dfappend.loc[x,"IP Address"],True,0,0,0,0,0,"Unknown",""]
		for x in df.index: #if any old devices are not in the new df, assumed off and presence turned off
			if not x in dfappend.index:
				df.loc[x,"Presence"]=False
			if x in dfappend.index:
				df.loc[x,"Presence"]=True
				df.loc[x,"Name"]=dfappend.loc[x,"Name"]
				df.loc[x,"Manufacturer"]=dfappend.loc[x,"Manufacturer"]
				df.loc[x,"IP Address"]=dfappend.loc[x,"IP Address"]	
	else:
		df=pd.read_csv("test.csv") # if no master file detected, new detection becomes master file
		df.set_index(df["MAC Address"],inplace=True,drop=True)
		df.drop("MAC Address",axis=1,inplace=True)
		df["Presence"] = True #all presence auto true
		df["RSSI Value 1"]=None
		df["RSSI Value 2"]=None
		df["RSSI Value 3"]=None
		df["Location X"]=None
		df["Location Y"]=None
		df["Membership"]="Unknown"
		df["RFID Tag"]=""
		df=df.astype({"RFID Tag":str})#IMPORTANT
def Location():
	global df
	#Location begins, opens RSSI values from the 3 csv files
	f1=open("/home/pi/esp32-tool/passive/loc1.csv")
	f2=open("/home/pi/esp32-tool/passive/loc2.csv")
	f3=open("/home/pi/esp32-tool/passive/loc3.csv")
	df1=pd.DataFrame(columns=["MAC Address","RSSI"])
	df2=pd.DataFrame(columns=["MAC Address","RSSI"])
	df3=pd.DataFrame(columns=["MAC Address","RSSI"])

	#1.28
	#Turns each csv into a dataframe and dumps excess values and weird unnecessary stuff	
	for x in f1:
		st=x.split(",")
		df1=df1._append({"MAC Address":st[2],"RSSI":int(st[3][0:len(st[3])-1])},ignore_index=True)	
	for x in f2:
		st=x.split(",")
		df2=df2._append({"MAC Address":st[2],"RSSI":int(st[3][0:len(st[3])-1])},ignore_index=True)					
	for x in f3:
		st=x.split(",")
		df3=df3._append({"MAC Address":st[2],"RSSI":int(st[3][0:len(st[3])-1])},ignore_index=True)

	for x in df.index:	#appends each mean RSSI value onto its designated device
		df.loc[x,"RSSI Value 1"]=df1.loc[df1.loc[:,"MAC Address"]==x]["RSSI"].mean()
		df.loc[x,"RSSI Value 2"]=df2.loc[df2.loc[:,"MAC Address"]==x]["RSSI"].mean()
		df.loc[x,"RSSI Value 3"]=df3.loc[df3.loc[:,"MAC Address"]==x]["RSSI"].mean()
		
		#find locations of device if all RSSI vals are located
		if(not np.isnan(df.loc[x,"RSSI Value 1"]) and not np.isnan(df.loc[x,"RSSI Value 2"]) and not np.isnan(df.loc[x,"RSSI Value 3"])):
			xy=calcLoc([df.loc[x,"RSSI Value 1"],df.loc[x,"RSSI Value 2"],df.loc[x,"RSSI Value 3"]])
			df.loc[x,"Location X"]=float(xy[sympy.symbols("x",real=True)])
			df.loc[x,"Location Y"]=float(xy[sympy.symbols("y",real=True)])
		#elif not pd.isnull(df.loc[x,"Location X"]) and not pd.isnull(df.loc[x,"Location Y"]):
			#df.loc[x,"Location X"]=np.nan
			#df.loc[x,"Location Y"]=np.nan	
		#print(df1.loc[df1.loc[:,"MAC Address"]==x]["RSSI"].mean()," 1")
		#print(df2.loc[df2.loc[:,"MAC Address"]==x]["RSSI"].mean()," 2")
		#print(df3.loc[df3.loc[:,"MAC Address"]==x]["RSSI"].mean()," 3")
	return		
def Membership():
	global df
	global trig_line
	#Membership
	trig_line.set_value(1)
	values= []
	try:
		end=time.time()+10
		values= []
		while time.time()<end:
			trig_line.set_value(0)
			id= inputimeout("Input ID: ",10)
			if(time.time()<end):
				values.append(id)
	except Exception:
		trig_line.set_value(1)
		print("Timeout occurred")
		time.sleep(5)
		rfids=[]
	for y in values:
		if not y in df["RFID Tag"].tolist():
			rfids.append(y)	
	for x in df.index:					
		if df.loc[x,"Membership"]=="Unknown":
			member=input("Enter Owner of "+df.loc[x,"Name"]+" ")
			member = member if member !="" else "Unknown"
			df.loc[x, "Membership"]=member
			trig_line.set_value(1)
			choice=input("Would you like to assign an ID? (Y/N) ")
			if(choice=="Y"):
				if(len(rfids)!=0):
					print("Choose a Tag from below to assign to ",df.loc[x,"Name"])
					for y in range(len(rfids)):
						print("(",y+1,") ",rfids[y])
					choice2=input(("Input a number, or leave empty for no assignment \n"))
					if choice2.isdigit() :
						choice2=int(choice2)
						if 0<=choice2<=len(rfids):					
							df.loc[x,"RFID Tag"]=rfids[choice2-1]
							rfids.remove(rfids[choice2-1])
					else:
						print("No Assignment Detected")
						df.loc[x,"RFID Tag"]=""	
				else:
					print("Ran out of Tags to assign")		
				#print(df["RFID Tag"].tolist())	
	return					
def printMembers():
	end=time.time()+10
	values= []
	try:
		while time.time()<end:
			trig_line.set_value(0)
			id= inputimeout("Input ID: ",10)
			if(time.time()<end):
				values.append(id)
	except Exception:
		print("Timeout occurred")
		print("Done")	
		trig_line.set_value(1)	
		time.sleep(5)
	
	for x in values:
		if x in df["RFID Tag"].tolist():
			print(df.loc[df.loc[:,"RFID Tag"]==x])
def openmenu():
	print("Pick an option:\n"+
		"(1) Scan Room for Devices\n"+
		"(2) Perform Extensive Nmap to nmapext.txt file (WARNING, CAN TAKE UP TO 50 MINUTES AND MAY BE HARD TO READ) \n"+
		"(3) Output Current Devices' Data\n"+
		"(4) Remove a Device from the Database\n"+
		"(5) Show the Tagged Devices \n"+
		"(6) Plot Found Devices\n"+
		"(7) Delete master.csv file\n"
		)
	
def plotDevices():
	df2=df[["Name","Presence","Location X","Location Y"]].copy()
	df2=df2.dropna(axis='rows')
	df2= pd.concat([df2,pd.DataFrame({"Name":["AP0","AP1","AP2"],"Presence":[True,True,True],"Location X":[0,2,3.5],"Location Y":[0,3,0]})],ignore_index=True)
	colors = np.array([x for x in range(0,len(df2)*10,10)])
	#print(colors)
	print(df2)
	for x in df2.index:
		if df2.loc[x,"Presence"]==True:
			labeln=df2.loc[x,"Name"]
		else:
			labeln=df2.loc[x,"Name"] + " (Last Known Location)"
		plt.scatter(df2.loc[x,'Location X'],df2.loc[x,'Location Y'],c=(random.uniform(0,1),random.uniform(0,1),random.uniform(0,1)),label=labeln)		
		#print(x , " " ,df2.loc[x,"Name"])
	plt.legend(loc='upper left')	
	plt.show()	
def removeDevice():
	macs=df.index
	for x in range(0,len(df.index)):
		print("("+str(x+1)+") "+df.loc[macs[x],"Name"])
		MAC= input("Input number of device you want to remove: ")
		if MAC.isdigit():
			MAC=int(MAC)
			if  0 <= MAC-1 < len(df.index) :
				df.drop(macs[MAC-1],inplace=True)
				#add option to remove by name	
def main():
	global df
	setuppins()
	attempts=3
	while(not login() and attempts > 1):
		print("Incorrect , attempts left: (",attempts-1,")\n\n")
		attempts -=1
		continue
	os.system('clear')
	if(attempts <=1):
		print("\n\n Tries exceeded, permission denied")
	while(True and attempts >1):
		trig_line.set_value(1)
		openmenu()
		option=input()
		if(option.isdigit()):
			option=int(option)
			if(option==1):
				setuppins()
				PresenceNmap()
				masterdataframesetup()
				input("Please press enter after you have run the ESPIDF clients and updated their CSVs")
				Location()
				choice=input("Would you like to assign any owners to any device?(Y/N)")
				if(choice=="Y"):
					Membership()
				df.to_csv("master.csv")
				print(df)
			if(option==2):
				os.system("sudo nmap -O -sC -sV -p- -T4 -oA advanced_scan_output 192.168.1.1/24 > nmapext.txt") 
			if(option==3):
				print(df)
			if(option==4):
				removeDevice()
				df.to_csv("master.csv")
			if(option==5):
				df=pd.read_csv("master.csv")
				printMembers()
			if(option==6):
				plotDevices()
			if(option==7):
				if os.path.exists("master.csv"):
				  os.remove("master.csv")
				  print("File removed successfully")
				else:
				  print("The file does not exist")
				
    # print(df)
    # df.to_csv("master.csv")

if __name__ == "__main__":
    main()
