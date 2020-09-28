H2 Prerequisites
```
sudo pip install mongodb
```


RESTful API Usage
```JSON
{
    "type": "Statistics",
    "Node": "ALL", 
    "AggregationLevel": "ALL",
    "StatFilter": [{"Top_N":"100"}],
    "MAC_src":"", 
    "MAC_dst":"", 
    "IP_src":"", 
    "IP_dst":"", 
    "Proto":"", 
    "Port_src":"", 
    "Port_dst":""
}
```
