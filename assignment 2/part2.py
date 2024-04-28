import sys
import _crypt
import _crack

if sys.argv[1] == "crypt":
    _crypt.crypt()
    
elif sys.argv[1] == "crack":
    _crack.crack()
