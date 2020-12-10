import ipfshttpclient

with ipfshttpclient.connect() as client:
    hash = "QmWj3jMsnKZLpApN9JLDFpf6qAp6tLpXnLLHJPH9H7iEZa"
    client.get(hash,'./incoming_file')

with open('./incoming_file/' + hash, 'rb') as File:
    File.read()
