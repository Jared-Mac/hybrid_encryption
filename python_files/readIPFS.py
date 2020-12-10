import ipfshttpclient

with ipfshttpclient.connect('/ip4/192.168.1.37/tcp/443/', auth=("pi","CaptainHoot117")) as client:
    hash = client.add('test.txt')['Hash']

    print(client.pin.ls(type="all"))

    client.pin.rm(hash)

    print(client.pin.ls(type="all"))