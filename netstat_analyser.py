#!/usr/bin/python

from Tkinter import *

import subprocess
import pwd
import os
import re
import glob

PROC_TCP = "/proc/net/tcp"

STATE = {
        '01':'ESTABLISHED',
        '02':'SYN_SENT',
        '03':'SYN_RECV',
        '04':'FIN_WAIT1',
        '05':'FIN_WAIT2',
        '06':'TIME_WAIT',
        '07':'CLOSE',
        '08':'CLOSE_WAIT',
        '09':'LAST_ACK',
        '0A':'LISTEN',
        '0B':'CLOSING'
        }

def load_content():

    with open(PROC_TCP,'r') as f:
        content = f.readlines()
        content.pop(0)
    return content

def hex2dec(s):
    return str(int(s,16))

def _ip(s):
    ip = [(hex2dec(s[6:8])),(hex2dec(s[4:6])),(hex2dec(s[2:4])),(hex2dec(s[0:2]))]
    return '.'.join(ip)

def remove_empty(array):
    return [x for x in array if x !='']

def convert_ip_port(array):
    host,port = array.split(':')
    return _ip(host),hex2dec(port)

def load_proc_id(inode):

    for item in glob.glob('/proc/[0-9]*/fd/[0-9]*'):
        try:
            if re.search(inode,os.readlink(item)):
                return item.split('/')[2]
        except:
            pass
    return None

def check_owner (inspec_object):
	try:
		if (inspec_object == '0.0.0.0') or (inspec_object == '127.0.0.1'):
			pass
		else:
			data = subprocess.check_output("whois %s | grep 'owner:\|Owner:\|netname:\|NetName:'"%inspec_object, shell=True)
			data = data.split(':')
			data[1] = data[1].lstrip()
			data[1] = data[1].replace('\n','')
			return data[1]
	except:
		print 'error: could not check the ip address owner'


def netstat():
    content=load_content()
    result = []
    for line in content:
		line = line.split(' ')
		line_array = remove_empty(line)
		l_host,l_port = convert_ip_port(line_array[1])
		r_host,r_port = convert_ip_port(line_array[2])
		tcp_id = line_array[0]
		state = STATE[line_array[3]]
		uid = pwd.getpwuid(int(line_array[7]))[0]
		inode = line_array[9]
		pid = load_proc_id(inode)
		try:
			exe = os.readlink('/proc/'+pid+'/exe')
		except:
			exe = None



		dest_owner = check_owner(r_host)

		nline = [tcp_id, uid, l_host+':'+l_port, r_host+':'+r_port, state, exe, dest_owner]

		result.append(nline)

    return result


#geoiplookup r_host
def main_program(event):
        print "TCP_ID  UID    LOCAL_HOST:PORT   REMOTE_HOST_PORT   STATE   PROCESS   REMOTE_OWNER"
        if __name__ == '__main__':
            netstat_data = netstat()

            for i in range(len(netstat_data)):
                for j in range(len(netstat_data[i])):
                    bar=Label(MainFrame,text=netstat_data[i][j],fg="yellow", bg="black")
                    bar.grid(row=(i+5),column=j)

            scrollbar = Scrollbar(MainFrame)
            scrollbar.grid(column=7,row=0)
            scrollbar.config(command=bar)


#GUI INTERFACE
root = Tk()

MainFrame = Frame(root, bg="black", height="450", width="800")
MainFrame.grid()

first_label = Label(MainFrame, text="NETSTAT ANALYSER", bg="black", fg="green", font=("Courier 10 Pitch", 14))
first_label.grid(column=3)

buttom_1 = Button(MainFrame, text="Scan connections", fg="red")
buttom_1.bind("<Button-1>", main_program)
buttom_1.grid(column=3, row=1)


desc_bar1 = Label(MainFrame, text = "     TCP ID    ", fg = "blue")
desc_bar1.grid(column=0, row=4)

desc_bar2 = Label(MainFrame, text = "     UID    ", fg = "blue")
desc_bar2.grid(column=1, row=4)

desc_bar3 = Label(MainFrame, text = "     LOCAL_HOST:PORT    ", fg = "blue")
desc_bar3.grid(column=2, row=4)

desc_bar4 = Label(MainFrame, text = "     REMOTE_HOST_PORT    ", fg = "blue")
desc_bar4.grid(column=3, row=4)

desc_bar5 = Label(MainFrame, text = "     STATE    ", fg = "blue")
desc_bar5.grid(column=4, row=4)

desc_bar6 = Label(MainFrame, text = "     PROCESS    ", fg = "blue")
desc_bar6.grid(column=5, row=4)

desc_bar7 = Label(MainFrame, text = "     REMOTE_HOST_OWNER    ", fg = "blue")
desc_bar7.grid(column=6, row=4)

cmd_pwd = subprocess.check_output("pwd").rstrip()+"/tux.png"

try:
    photo = PhotoImage(file=cmd_pwd)
    w = Label(MainFrame, image=photo, bg="black")
    w.photo = photo
    w.grid(row=0, column=6, rowspan=2, sticky=W+S)

except:
    pass

root.mainloop()
