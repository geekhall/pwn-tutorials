import os
import hashlib


x=hashlib.sha256()
x.update(b'1234')
print x.hexdigest()

 
