from remote import connect, ROOT
import io
import tarfile

client = connect()
try:
    command = "sudo -S -p '' docker exec zensheild-web-1 tar cz --exclude=__pycache__ --exclude='*.pyc' -C /app fastapi_app static run_fastapi.py"
    stdin, stdout, stderr = client.exec_command(command)
    stdin.write(client._maintenance_password + '\n')
    stdin.flush()
    archive = stdout.read()
    if stdout.channel.recv_exit_status():
        raise RuntimeError('Source retrieval failed')
    target = ROOT / 'deployed-source'
    target.mkdir(exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as tar:
        tar.extractall(target, filter='data')
    print('Application source retrieved to deployed-source')
finally:
    client.close()
