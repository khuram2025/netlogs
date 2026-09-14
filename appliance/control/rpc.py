import http.client
import json
import socket

class Connection(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect('/run/zenshield/agent.sock')

def call(operation, **body):
    connection = Connection('localhost', timeout=120)
    try:
        connection.request('POST', '/rpc', json.dumps({'operation': operation, 'body': body}),
                           {'Content-Type': 'application/json'})
        response = connection.getresponse()
        result = json.loads(response.read())
        if response.status != 200:
            raise ValueError(result.get('error', 'Management request failed'))
        return result
    finally:
        connection.close()
