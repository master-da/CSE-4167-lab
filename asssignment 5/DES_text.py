import sys
from BitVector import BitVector
from DES import DES

CHUNK_SIZE = 8

if __name__ == "__main__":
    
    encrypter: DES = None
    
    with open(sys.argv[2], 'r') as f:
        text = f.read()
        encrypter = DES(text)        
    
    with open(sys.argv[1], 'rb') as f:
        with open(sys.argv[3], 'wb') as out:
            text = f.read(CHUNK_SIZE)
            print("DES text:", text)
            text = BitVector(rawbytes = text)

            if text.length() < 64: text.pad_from_right(64 - text.length())

            crypted: BitVector = None
            
            if sys.argv[1] == 'encrypted.txt': crypted = encrypter.decrypt(text)
            else: crypted = encrypter.encrypt(text)
            
            crypted.write_to_file(out)
            print("output written to file:", sys.argv[3])
