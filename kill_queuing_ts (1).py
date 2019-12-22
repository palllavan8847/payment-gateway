'''
Author : Rajapallavan.J
This module is used to fetch all the queuing(running) process from ts(task spooler) and kill it by means of process id finally print the killed process
'''
import subprocess
import re
import os
import signal

#get all ts process 
task_list = subprocess.Popen(["tsp"], stdout = subprocess.PIPE)
task_output = task_list.communicate()
task_output = task_output[0].split("\n")
headers = task_output[0].split()
####No queuing tasks ###
if re.findall(r'\d+', headers[-1].split('/')[0])[0] == '0':
	raise Exception("There is no queuing tasks")
kill_process_list = []
for index_range, process_list in enumerate(task_output):
	# if header then continue
	if index_range == 0:
		continue
	task_detail = process_list.split()
	# check whether the process is running
	if task_detail and task_detail[headers.index('Output') - 1] == "running":
		process_name = task_detail[-1].split('/')[-1]
		# check process already get killed if killed then continue
		if process_name in kill_process_list:
			continue
		try:
			# get process id
			get_process = subprocess.Popen(("ps", "-ef"), stdout = subprocess.PIPE)
			get_process_output = subprocess.check_output(('grep', process_name), stdin = get_process.stdout)
			get_process.wait()
		except Exception as e:
			print "Error is %s so unable to get the process details for %s" %(str(e.message), process_name)
			continue
		get_process_output = get_process_output.strip().split('\n')
		#kill process by means of process id
		try:
			filter(lambda process_detail: os.kill(int(process_detail.split()[1]), signal.SIGKILL), get_process_output)
		except Exception as e:
			print "Error is %s so unable to kill process %s" %(str(e.message), process_name)
			continue
		#append in a list for duplicate checking
		kill_process_list.append(process_name)
print "Killed process are : %s"%(', '.join(kill_process_list))