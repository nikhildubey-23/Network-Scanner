This is the Network scanning tool made for linux operating system it is use to find the live connected host for given range of ip addresses and it is also use to tell the vendor name name of that ip addresses if it's present very soon we are going to get the next update for this tool

{note:- this tool were not going to run in windows operating system }

before we going to use run this command :
    pip install -r requirement.txt

for to install  its dependencies module 

usage: main.py [-h] [--s START_IP] [--e END_IP]

Network Scanner

options:
  -h, --help    show this help message and exit
  --s START_IP  start Ip address in the format
                x.x.x.x
  --e END_IP    End ip address in the formate
                x.x.x.x
                       
example :- python3 main.py --s 192.168.112.1 --e 192.168.112.200
