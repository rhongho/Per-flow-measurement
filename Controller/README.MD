### Prerequisites
```
sudo pip install mongodb
```
### Run RFlow_Collector and RESTful API
```
python3 RFlow_Collector.py
python3 RESTful_API.py
```

### RESTful API Usage

RFlow_Object Example
```JSON
{
    "type": "Statistics",
    "ID": "1", 
    "Layer": "4",
    "MAC_src":"MAC_1", 
    "MAC_dst":"MAC_2", 
    "IP_src":"IP_1", 
    "IP_dst":"IP_2", 
    "Proto":"6", 
    "Port_src":"23", 
    "Port_dst":"60542"
}
```
To access flow statistics using RFlow+ RESTful API, use HTTP GET and list RFlow_Object as the body. Note: remove a field in RFlow_Object to enable wirdcard rule. 

For instanse, the follwing RFlow_Object accesses all flow statistics:
```JSON
{
    "type": "Statistics"
}
```
