from Crypto.PublicKey import RSA

keys = RSA.generate(1024)

priv_file = open('private_key.pem', 'wb')
priv_file.write(keys.exportKey())
priv_file.close()

pub_file = open('public_key.pem', 'wb')
pub_file.write(keys.publickey().exportKey())
pub_file.close()
