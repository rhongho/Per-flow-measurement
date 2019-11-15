# Sampling
This is an implementation of network traffic monitoring application using libpcap. 

The sketch (compact data structure) and hash table are leveraged to perform the scalable counting.
The code is the flow estimation part of Rflow+ work (INFOCOM 2017, paper link provided), but using more efficient sketch design (under review). 

https://ieeexplore.ieee.org/stamp/stamp.jsp?arnumber=8056995

<h2> Compile</h2>

gcc -o rflow rlfow.c hash.c -libpcap


<h2>Execute</h2>
Format: ./File_name Interface Layer_to_monitor\n

Example: ./rflow eth0 3
