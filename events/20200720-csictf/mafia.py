from pwn import *

conn = remote('chall.csivit.com',30721)
friends = [i for i in range(1,301)]

beg = 1
end = 1000000
while len(friends) > 0:
	cur_value = (beg + end) // 2
	G = []
	E = []
	for x in friends:
		conn.send(f'1 {x} {cur_value}\n')
		v = conn.recvline(1).decode()[0]
		if v == 'G': 
			G.append(x)
		elif v == 'E': 
			E.append(x)
	print()
	if len(G) > 0:
		friends = G[:]
		beg = cur_value + 1
	elif len(E) > 0:
		conn.send('2 '+ str(cur_value) +"\n")
		while True:
			print(conn.recvline())
	else:
		end = cur_value - 1
