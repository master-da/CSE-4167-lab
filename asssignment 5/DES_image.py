import sys
from tqdm import tqdm
from BitVector import BitVector
from DES import DES

CHUNK_SIZE = 8

if __name__ == "__main__":
    
    encrypter: DES = None
    
    with open(sys.argv[2], 'r') as f:
        text = f.read()
        encrypter = DES(text)        
    
    with open(sys.argv[1], 'rb') as f:
        
        magic = f.readline()
        dim = f.readline()
        maxval = f.readline()
        
        with open(sys.argv[3], 'wb') as out:
            
            out.write(magic)
            out.write(dim)
            out.write(maxval)
            
            
            crypted: BitVector = BitVector(size = 0)
            
            image = f.read()

            for i in tqdm(range(0, len(image), 8)):

                chunk = BitVector(rawbytes = image[i:i+8])
                # print(i, len(image))

                if chunk.length() < 64: chunk.pad_from_right(64 - chunk.length())

            
                if sys.argv[1] == 'image_enc.ppm': crypted = crypted + encrypter.decrypt(chunk)
                else: crypted = crypted + encrypter.encrypt(chunk)
            
            crypted.write_to_file(out)
            print("output written to file:", sys.argv[3])
