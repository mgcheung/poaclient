#!/usr/bin/python
import urllib2
import base64
import binary
import sys

TARGET = 'http://crypto-class.appspot.com/po?er='
CIPHERTEXT = 'F20BDBA6FF29EED7B046D1DF9FB7000058B1FFB4210A580F748B4AC714C001BD4A61044426FB515DAD3F21F18AA577C0BDF302936266926FF37DBF7035D5EEB4'
#--------------------------------------------------------------
# padding oracle
# This module allows one to mount Padding Oracle Attacks
#--------------------------------------------------------------

#This function will take an array of arrays of integers and flatten and convert to a string in hex.
#This allows us to easily construct values to submit to the oracle.
def array_to_string(array_of_array_of_ints):
    return_string=""
    for i in range(len(array_of_array_of_ints)):
        for j in range(len(array_of_array_of_ints[i])):
            return_string+="%0.2x"%array_of_array_of_ints[i][j]
    return return_string

#xor int arrays
def xor_array(array1,array2):
    if len(array1)!=len(array2):
        sys.stderr.write("Trying to xor arrays of different sizes. Aborting.")
        sys.exit()
    return [array1[i]^array2[i] for i in range(len(array1))]

class InvalidLength(Exception):
    def __str__(self):
        return "Invalid length of ciphertext"

#To generalize the PaddingOracle class we pass it a request argument.  It must provide a method for querying the oracle by taking in a token.
class Request():
    def __init__(self,Target):
        self.TARGET = Target    # Target URL

    def query(self, token):
        try:
            target = self.TARGET+ urllib2.quote("".join(token))
        except:
            print token
            sys.exit(-1)
        req = urllib2.Request(target)         # Send HTTP request to server 
        try:
            f = urllib2.urlopen(req)          # Wait for response
        except urllib2.HTTPError, e:          
            if e.code == 404:
                return True # good padding
            return False # bad padding

# This class implements a Padding Oracle Attack by taking a class that performs the querying and a string representing the token to decrypt
class PaddingOracle():
    def __init__(self,Request):
        self.BLOCKSIZE=16        # Blocksize of the cipher
        self.REQUEST=Request     # The object that will make the query
        # This function creates the next pad vector and returns a block sized array
    def increment_pad(self):
        if len(self.pad)==self.BLOCKSIZE:
            self.pad = [1]
        else:
            for i in range(len(self.pad)):
                self.pad[i]+=1
            self.pad.append(len(self.pad)+1)
        return [0]*(self.BLOCKSIZE-len(self.pad))+self.pad

    
    # This function runs the attack
    def attack(self,Ciphertext):
        if len(Ciphertext)%(2*self.BLOCKSIZE) != 0:
            raise(InvalidLength)
        self.ciphertext=[Ciphertext[i*2*self.BLOCKSIZE:(i+1)*2*self.BLOCKSIZE] for i in range(len(Ciphertext)/(2*self.BLOCKSIZE))]         # This will be an array of blocks from the token where each block is an array of integers
        self.pad=[]                 
        print "[+] Breaking up the ciphertext into an array of blocks"
        # Convert ciphertext string into an array of block size arrays of integers
        # Initializing the plaintext
        print "[+] Initializing the plaintext"
        self.plaintext=[[0 if i<len(self.ciphertext)-2 else 1]*(self.BLOCKSIZE) for i in range(len(self.ciphertext)-1)]

        # The attack works from the end of the ciphertext to the beginning
        print "[+] Beginning attack"
        for i in range(len(self.plaintext)-1,-1,-1):
            # After each block is decrypted, we remove it and only submit modifications of the previous blocks
            # We work one byte at a time in each block incrementing the value of our guess for the plaintext, xor the last bytes with the number of those bytes and the original ciphertext
            self.token=self.ciphertext[:i+2]
            for j in range(len(self.plaintext[i])-1,-1,-1):
                    pad_and_guess=self.increment_pad()
                    # If we know this is the last block in the original ciphertext and we have learned the last byte, we know the pad and thus we know some of the bytes
                    # in the last block.  This allows us to speed up the process at the same time prevents a bug when initializing the plaintext to all zeros
                    if i == len(self.plaintext)-1 and j < len(self.plaintext[i])-1 and j > len(self.plaintext[i])-1-self.plaintext[i][-1]:
                        self.plaintext[i][j]=self.plaintext[i][-1]
                    else:
                        # Here is where we increment the values in the guess of the plaintext and try the query
                        for k in range(256):
                            self.token[i]=binary.byteTohex(xor_array(xor_array(map(ord,base64.b16decode(self.ciphertext[i])),self.plaintext[i]),pad_and_guess))
#                            print self.token[i]
                            sys.stdout.write("\r"+"Plaintext so far: "+array_to_string(self.plaintext))
                            # If we get True from the query, that means we have a valid pad and thus decrypted the byte we are working on
                            querylength=len(self.token)
                            if self.REQUEST.query(self.token[querylength-(2*16*2):]):
                                if i==(len(self.plaintext)-1) and j==(len(self.plaintext[i])-1):
                                    pad=self.plaintext[i][j]
                                    self.plaintext[i]=[0]*(self.BLOCKSIZE-pad)+[pad]*pad
                                break
                            else:
                                self.plaintext[i][j]+=1
        # Here we flatten the plaintext
        plaintext_array = self.plaintext[0]
        for i in range(1,len(self.plaintext)):
            plaintext_array+=self.plaintext[i]
        # We remove the pad bytes
        plaintext_array=plaintext_array[:len(plaintext_array)-plaintext_array[-1]]
        # Now we convert the plaintext bytes into a string converting to ASCII
        plaintext_string=""
        for i in range(len(plaintext_array)):
            plaintext_string+=chr(plaintext_array[i])
        print "\n"+plaintext_string

# To test this module we can run it as a script with the hard coded values for TARGET and CIPHERTEXT
if __name__ == "__main__":
    req = Request(TARGET)
    po = PaddingOracle(req)
    po.attack(CIPHERTEXT)       
