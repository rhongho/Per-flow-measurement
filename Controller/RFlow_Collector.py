import threading 
import socket 
import json
from pymongo import MongoClient
from _thread import *
  
print_lock = threading.Lock() 

myclient = MongoClient('localhost', 27017)
mydb = myclient.RflowCollector
FlowCol = mydb.FlowRecord
Rules = mydb.FlowRule


# thread function 
def threaded(c): 
    while True: 
  
        # data received from client 
        data = c.recv(4096)
        if not data: 
            print('No Data') 
            
            # lock released on exit 
            print_lock.release() 
            break
  	
        json_data = json.loads(data)
        ID = json_data["ID"]
        Layer = json_data["Layer"]
        for x in range(len(json_data["Flow_Record"])):
        	for y in json_data["Flow_Record"]:
            		if json_data["Layer"] == 2:
            			dict={"ID":ID, "Layer":Layer, "Hash": y[0], "src_MAC": y[1],"dst_MAC": y[2]}
            			if FlowCol.count_documents(dict) > 0:
            				print(FlowCol.find_one(dict)["counter"])
            				ndict={"$set": {"ID":ID, "Layer":Layer, "Hash": y[0], "src_MAC": y[1],"dst_MAC": y[2], "counter":FlowCol.find_one(dict)["counter"] + float(y[3])}}
            				FlowCol.update_one(dict, ndict)
            			else:
            				dict={"ID":ID, "Layer":Layer, "Hash": y[0], "src_MAC": y[1],"dst_MAC": y[2], "counter":float(y[3])}
            				FlowCol.insert_one(dict)
            		
            		if json_data["Layer"] == 3:
            			dict={"ID":ID, "Layer":Layer, "Hash": y[0], "src_IP": y[1],"dst_IP": y[2]}
            			if FlowCol.count_documents(dict) > 0:
            				print(FlowCol.find_one(dict)["counter"])
            				ndict={"$set": {"ID":ID, "Layer":json_data["Layer"], "Hash": y[0], "src_IP": y[1],"dst_IP": y[2], "counter":FlowCol.find_one(dict)["counter"] + float(y[3])}}
            				FlowCol.update_one(dict, ndict)
            			else:
            				dict={"ID":ID, "Layer":Layer, "Hash": y[0], "src_IP": y[1],"dst_IP": y[2], "counter":float(y[3])}
            				FlowCol.insert_one(dict)
            		
            		if json_data["Layer"] == 4:
            			dict={"ID":ID, "Layer":Layer, "Hash": y[0], "src_IP": y[1],"dst_IP": y[2], "Porto":y[3], "src_Port":y[4], "dst_Port":y[5]}
            			if FlowCol.count_documents(dict) > 0:
            				print(FlowCol.find_one(dict)["counter"])
            				ndict={"$set": {"ID":ID, "Layer":json_data["Layer"], "Hash": y[0], "src_IP": y[1],"dst_IP": y[2], "Porto":y[3], "src_Port":y[4], "dst_Port":y[5], "counter":FlowCol.find_one(dict)["counter"] + float(y[6])}}
            				FlowCol.update_one(dict, ndict)
            			else:
            				dict={"ID":ID, "Layer":Layer, "Hash": y[0], "src_IP": y[1],"dst_IP": y[2], "Porto":y[3], "src_Port":y[4], "dst_Port":y[5], "counter":float(y[6])}
            				FlowCol.insert_one(dict)

    c.close() 
  
  
def Main(): 
    host = "" 
  
    # reverse a port on your computer 
    # in our case it is 12345 but it 
    # can be anything 
    port = 8080
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
    s.bind((host, port)) 
    print("socket binded to port", port) 
  
    # put the socket into listening mode 
    s.listen(5) 
    print("socket is listening") 
  
    # a forever loop until client wants to exit 
    while True: 
  
        # establish connection with client 
        c, addr = s.accept() 
  
        # lock acquired by client 
        print_lock.acquire() 
        print('Connected to :', addr[0], ':', addr[1]) 
  
        # Start a new thread and return its identifier 
        start_new_thread(threaded, (c,)) 
    s.close() 
  
  
if __name__ == '__main__': 
    Main() 

