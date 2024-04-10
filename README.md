This tool is designed for the Linux operating system and helps to find live connected hosts within a given range of IP addresses. Additionally, it can also identify the vendor name associated with each IP address. I am currently working on an update for this tool, which will be released soon.

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
