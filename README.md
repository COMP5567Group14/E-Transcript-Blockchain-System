# E-Transcript-Blockchain-System
Usage
All command:

Node Network.
Copy the code resource to a new directory. While the miner before was running, then:

For Student node Initialization.
$ cd {Student_directory}
$ python console node run <ip: port1>
$ python console node add <ip: port2>
$ python console node add <ip: port3>

For Teacher node Initialization.
$ cd {Teacher_directory}
$ python console node run <ip: port2>
$ python console node add <ip: port1>
$ python console node add <ip: port3>

For Miner node Initialization.
$ cd {Miner_directory}
$ python console node run <ip: port3>
$ python console node add <ip: port1>
$ python console node add <ip: port2>

Create Teacher/ Miner/ Student Account.
$ python console account create

Teacher check Students' Accounts.
$ python console account student

Run the Miner.
$ python console miner start <ip: port>

GPA Input.
$ python console tx transcript <StudentID> <GPA>

Transcript list.
$ python console tx list

Blockchain shows.
$ python console blockchain list

Query
Teacher Query.
$ python console query_teacher studentid <StudentID>
Teacher Range Query.
$ python console query_teacher range <from_range> <to_range> <order> <StudentID_only>
Student Query.
$ python console query_student studentid <StudentID> <Student's Private Key>

When students' accounts are created, they'll broadcast to teacher and miner nodes.
When a new block is mined, the block and transactions will broadcast to other nodes.

