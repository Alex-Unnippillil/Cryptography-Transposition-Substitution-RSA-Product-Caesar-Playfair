# Transposition and Substitution ,RSA and Product, Caesar and Playfair Algorithm
import math, random, sys
from math import gcd

# Theses are possibilities for different output of encryption
# LETTERS = r""" !"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXY Z[\]^_`abcdefghijklmnopqrstuvwxyz{|}~"""
LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


class Message:
    def __init__(self, key, Message, playfair):
        # Transposition, Substitution
        self._key = key
        # Message will be passed into message class
        # Type of Cipher will also be passed in
        self.Message = Message
        self.key = []
        # RSA Variables
        self.p = 0
        self.q = 0
        self.n = 0
        self.Phi_N = 0
        self.e = 0
        self.d = 0

        # Playfair
        self.playfair = playfair
        self.seq = [
           ['a', 'b', 'c', 'd', 'e'],
           ['f', 'g', 'h', 'i', 'j'],
               ['k', 'l', 'm', 'n', 'o'],
               ['p', 'q', 'r', 's', 't'],
               ['u','v', 'w', 'x', 'y']]
        shir = ''
        for l in self.playfair:
            shir = shir + l + ' '
        shir.rstrip()
        shir = shir.split()
        semif = []

        for x in shir:
            if x in semif:
                pass
            else:
                semif.append(x)
        last = [[], [], [], [], []]
        kl = 0
        nk = 0
        for char in semif:
            if nk % 5 == 0 and nk != 0:
                kl += 1
                nk = 0

            last[kl].append(char)
            nk += 1

        for x in self.seq:
            for y in x:
                if y in last[0] \
                        or y in last[1] \
                        or y in last[2] \
                        or y in last[3] \
                        or y in last[4]:
                    pass
                else:
                    if nk % 5 == 0 and nk != 0:
                        kl += 1
                        nk = 0

                    last[kl].append(y)
                    nk += 1

        self.seq = last

        for x in range(5):
            for y in range(5):
                if self.seq[x][y] == 'x':
                    break
        self.x = [x, y]

        # print(last, '\n')


    # RSA Methods Start
    # Random prime number generator
    def ChooseAPrime(self):
        prime = False
        while prime == False:
            RandomPrime = random.randint(1, 1000)
            for number in range(2, RandomPrime):
                if (RandomPrime) == 1:
                    prime = False
                    print("number is 1")
                elif (RandomPrime % number) == 0:
                    prime = False
                    break
                else:
                    prime = True

            return RandomPrime

    # Find product of 2 random primes and totient
    def ProductofPrimes(self):
        self.p = Message.ChooseAPrime(self)
        self.q = Message.ChooseAPrime(self)
        self.n = self.p * self.q

        # Calculate the totient
        self.Phi_N = (self.p - 1) * (self.q - 1)

    # Find an e that is relatively prime to the totient
    # A number is realatively prime if they both share a common factor of 1 and only one in common
    # Also if their GCD is equal to one
    def e_Picker(self, Phi_N):
        Coprime_List = []
        for number in range(0, 1000):
            if gcd(number, Phi_N) == 1:
                Coprime_List.append(number)
        self.e = random.choice(Coprime_List)

    # Have to change this function
    # Euclidian and mod inverse
    def egcd(a, b):
        if a == 0:
            return (b, 0, 1)
        else:
            g, y, x = Message.egcd(b % a, a)
            return (g, x - (b // a) * y, y)

    # Change this function
    def modinv(a, m):
        g, x, y = Message.egcd(a, m)
        if g != 1:
            return None
        else:
            return x % m

    # Change this function
    def d_Picker(self, e, Phi_N):
        # (e*d) mod Phi(n) = 1
        self.d = Message.modinv(e, Phi_N)

    def Gen_RSA_Keys(self):
        # Choose 2 random prime numbers and find their product
        # As well as totient
        Message.ProductofPrimes(self)
        # Pick an e with respect to totient(Phi(n))
        Message.e_Picker(self, self.Phi_N)
        Message.d_Picker(self, self.e, self.Phi_N)
        self.key = (self.e, self.n, self.d)
    # Substitution
    # Checks for errors and repetition
    # Makes sure that it's valid
    def checkValidKey(self, key):
        keyList = list(key)
        lettersList = list(LETTERS)
        keyList.sort()
        lettersList.sort()
        if keyList != lettersList:
            sys.exit("There is an error in the key or symbol set.")

    # Substitution
    # This retrieves a random key
    def getRandomKey(self):
        key = list(LETTERS)
        random.shuffle(key)
        return ''.join(key)

    # Substitution
    def substituteMessage(self, key, message, mode):
        translated = ''
        charsA = LETTERS
        charsB = key
        # This decrypts the message
        # It reverses the encryption block of code
        if mode == 'decrypt':
            charsA, charsB = charsB, charsA
        # This encrypts the message
        for symbol in message:
            if symbol.upper() in charsA:
                symIndex = charsA.find(symbol.upper())
                if symbol.isupper():
                    translated += charsB[symIndex].upper()
                else:
                    translated += charsB[symIndex].lower()
            else:
                translated += symbol
        return translated

    # Product
    def productMessage(self, key, message, mode):
        # This stores the encrypted/decrypted message string
        translated = []

        keyIndex = 0
        key = key.upper()
        # loop through each character in message
        for symbol in message:
            num = LETTERS.find(symbol.upper())
            # -1 means symbol.upper() was not found in LETTERS
            if num != -1:
                if mode == 'encrypt':
                    # add if encrypting
                    num += LETTERS.find(key[keyIndex])
                elif mode == 'decrypt':
                    # subtract if decrypting
                    num -= LETTERS.find(key[keyIndex])
                # handle the potential wrap-around
                num %= len(LETTERS)
                # add the encrypted/decrypted symbol to the end of translated.
                if symbol.isupper():
                    translated.append(LETTERS[num])
                elif symbol.islower():
                    translated.append(LETTERS[num].lower())
                # move to the next letter in the key
                keyIndex += 1
                if keyIndex == len(key):
                    keyIndex = 0
                    # The symbol was not in LETTERS, so add it to translated as is.
            else:
                translated.append(symbol)
        return ''.join(translated)


class plaintextMsg(Message):
    def __init__(self, key, Message, playfair):
        super().__init__(key, Message, playfair)
        self.Message = Message
        # RSA
        self.Encrypted_chars = []

    # Playfair
    def PFencrypt(self, sentence):
        sentencefirst = sentence.replace(' ', '')
        print(sentence)

        if len(sentencefirst) % 2 == 1:
            sentencefirst = sentencefirst + 'x'
        word = ''
        i = 0
        for l in sentencefirst:
            if i % 2 == 0 or i == 0:
                word = word + l
                i += 1
            else:
                word = word + l + ' '
                i += 1
        print(word)

        word = word.split()
        RQ = -1
        SQ = -1

        code = ''
        for a in word:
            for x in range(5):
                try:
                    RQ = self.seq[x].index(a[0])
                except:
                    continue

                if RQ != -1:
                    break
            for f in range(5):
                try:
                    SQ = self.seq[f].index(a[1])
                except:
                    continue

                if SQ != -1:
                    break
            if f == x and RQ == SQ:
                f = self.x[0]
                SQ = self.x[1]
            if f == x:
                code = code + self.seq[x][RQ % 4 + 1] \
                       + self.seq[f][SQ % 4 + 1] + ' '
            elif RQ == SQ:
                code = code + self.seq[x % 4 + 1][RQ] \
                       + self.seq[f % 4 + 1][SQ] + ' '
            else:
                code = code + self.seq[x][SQ] \
                       + self.seq[f][RQ] + ' '

        print(code)

    # Caesar
    def Caesarencryption(self):
        message = Imgs
        shift_number = int(input("Enter the shift number for your encryption: "))  # 1-26 1 being "A" and 26 being "Z"
        encrypt_text = ""
        message = message.lower()
        for r in range(len(message)):
            if ord(message[r]) == 32:  # ord() givin a string, it gives back an intiger
                encrypt_text += chr(ord(message[r]))  # ASCII is converted back to character with the use of chr()

            elif (ord(message[r]) + shift_number > 90) and (ord(message[r]) <= 96):
                # it moves the 'A' back to "Z" after this
                temp = (ord(message[r]) + shift_number) - 90
                encrypt_text += chr(64 + temp)
            else:
                encrypt_text += chr(ord(message[r]) + shift_number)

        print("Encrypted: " + encrypt_text)

    # RSA
    # Each string character is entered into a list according to it's ascii value
    # Then the RSA encryption is run on the ASCII value
    def RSA_Encryption(self):
        Char_int_Value = []

        for char in self.Message:
            Char_int_Value.append(ord(char))

        for chars in Char_int_Value:
            self.Encrypted_chars.append((int(chars) ** self.e) % self.n)

        return ("Encrypted Key: {}, Keys(e,n,d){},{},{}".format(self.Encrypted_chars, self.e, self.n, self.d))

    # Transposition
    # Encrypting the message
    def transencryptmessage(self, message):
        ciphertext = [''] * self._key
        for col in range(self._key):
            pointer = col
            while pointer < len(message):
                ciphertext[col] += message[pointer]
                pointer += self._key
        return ''.join(ciphertext)

    # Substitution
    # Calling the encryption
    def subencryptMessage(self, key, message):
        return Message.substituteMessage(self, key, message, "encrypt")
    # Product
    # Calling the encryption
    def productencryptMessage(self, key, message):
        return Message.productMessage(self, key, message, 'encrypt')

class ciphertextMsg(Message):
    def __init__(self, key, Message, playfair):
        super().__init__(key, Message, playfair)
        self.Encrypted_Message = Message
        # RSA
        self.n = 0
        self.d = 0
        self.Decrypted_chars = []

    # Caesar
    def Caesardecryption(self):
        encrpted_message = input("Enter the string that was encrypted here: ")
        shift_number = int(input("Enter the shift number that was used for the encryption: "))

        decrypt_text = ""
        encrpted_message = encrpted_message.lower()

        for r in range(len(encrpted_message)):
            if ord(encrpted_message[r]) == 32:
                decrypt_text += chr(ord(encrpted_message[r]))
            elif (ord(encrpted_message[r]) - shift_number) < 65:
                temp = (ord(encrpted_message[r]) - shift_number) + 26
                decrypt_text += chr(temp)
            else:
                decrypt_text += chr(ord(encrpted_message[r]) - shift_number)

        print("Decrypted Text: " + decrypt_text)

    # Transposition
    # Decryption for Transposition
    def transdecryptmessage(self, message):
        columns = math.ceil(len(message) / self._key)
        rows = self._key
        shadedboxes = (columns * rows) - len(message)
        plaintext = [''] * columns
        col = 0
        row = 0
        for symbol in message:
            plaintext[col] += symbol
            col += 1
            if (col == columns) or (col == columns - 1 and row >= rows - shadedboxes):
                col = 0
                row += 1
        return ''.join(plaintext)

    # Substitution
    # Calling the decryption
    def subdecryptMessage(self, key, message):
        return Message.substituteMessage(self, key, message, "decrypt")
    # Product
    # Calling the decryption
    def productdecryptMessage(self, key, message):
        return Message.productMessage(self, key, message, 'decrypt')

    # RSA
    # Performs decryption on the encrypted Ascii keys
    # Stores them in a list one by one and then converts the decrypted ascii keys
    # Back into plain text
    def RSA_Decryption(self):
        Encrypted_input = self.Encrypted_Message
        try:
            self.d = int(input("Enter the private key(as encrypted): "))
            self.n = int(input("Enter n: "))
            self.DecryptedKeys = []
            Encrypted_input = [x.strip() for x in Encrypted_input.split(',')]
            Encrypted_input = [int(x) for x in Encrypted_input]

            for chars in Encrypted_input:
                self.DecryptedKeys.append((chars ** self.d) % self.n)

            m_string = ""

            for char in self.DecryptedKeys:
                m_string += chr(char)

            return "\nDecrypted Message: {}".format(m_string)
        except ValueError:
            print("You have entered invalid key values")


if __name__ == '__main__':
    All_outputs = []

    while True:
        Imgs = input("Enter what you want encrypted: ")

        # Choose random encryption
        encryption = random.randrange(1, 6)

        if encryption == 1:
            print("RSA")
            message = Imgs
            while True:
                mode = str(input("Would you like to 'encrypt' or 'decrypt' or 'next' or 'STOP': "))
                if mode == 'encrypt':
                    # It works but once added in it will not
                    Current_Encrypt = plaintextMsg(key='', Message=message, playfair='')
                    Current_Encrypt.Gen_RSA_Keys()
                    print(Current_Encrypt.Gen_RSA_Keys())
                    All_outputs.append(message + ": " + Current_Encrypt.RSA_Encryption())
                elif mode == 'decrypt':
                    pass
                elif mode == 'next':
                    break
                elif mode == 'STOP':
                    for items in All_outputs:
                        print('\n', items, '\n')
                    sys.exit("Service Terminated! Goodbye.")
                else:
                    print("There has been an error.")

        elif encryption == 2:
            print("Substitution")
            key = ''
            mgs = Message(key, Message, playfair='')
            plain = plaintextMsg(key, Message, playfair='')
            crypt = ciphertextMsg(key, Message, playfair='')
            myMessage = Imgs
            while True:
                # Asks user for mode to preform
                mode = str(input("Would you like to 'encrypt' or 'decrypt' or 'next' or 'STOP': "))
                if mode == 'encrypt':
                    # Get random key
                    # Checks validation of key
                    myKey = mgs.getRandomKey()
                    mgs.checkValidKey(myKey)
                    # Calls encryption
                    translated = plain.subencryptMessage(myKey, myMessage)
                    # Prints output
                    print('Using key: %s' % (myKey))
                    print("Encryption is ", translated)
                    All_outputs.append(myMessage + ": " + translated + "Using:" + myKey)
                elif mode == 'decrypt':
                    # To use the different key change it here and at the very top
                    # myKey = r""" !"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXY Z
                    #    [\]^_`abcdefghijklmnopqrstuvwxyz{|}~"""
                    myKey = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                    # Calls decryption
                    translated = crypt.subdecryptMessage(myKey, myMessage)
                    # Prints output
                    print("Decryption is ", translated)
                    All_outputs.append(myMessage + ": " + translated + "Using:" + myKey)
                elif mode == 'next':
                    # To continue to a different cipher
                    break
                elif mode == 'STOP':
                    for items in All_outputs:
                        print('\n', items, '\n')
                    sys.exit("Service Terminated! Goodbye.")
                else:
                    print("There has been an error.")

        elif encryption == 3:
            print("Product")
            key = ''
            mgs = Message(key, Message, playfair='')
            plain = plaintextMsg(key, Message, playfair='')
            crypt = ciphertextMsg(key, Message, playfair='')
            myMessage = Imgs
            while True:
                # Asks user for mode to preform
                mode = str(input("Would you like to 'encrypt' or 'decrypt' or 'next' or 'STOP': "))
                if mode == 'encrypt':
                    # Get random key
                    # Checks validation of key
                    myKey = mgs.getRandomKey()
                    mgs.checkValidKey(myKey)
                    # Calls encryption
                    translated = plain.productencryptMessage(myKey, myMessage)
                    # Prints output
                    print('Using key: %s' % (myKey))
                    print("Encryption is ", translated)
                    All_outputs.append(myMessage + ": " + translated + "Using:" + myKey)
                elif mode == 'decrypt':
                    myKey = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                    # Calls decryption
                    translated = crypt.productdecryptMessage(myKey, myMessage)
                    # Prints output
                    print('Using key: %s' % (myKey))
                    print("Decryption is ", translated)
                    All_outputs.append(myMessage + ": " + translated + "Using:" + myKey)
                elif mode == 'next':
                    # To continue to a different cipher
                    break
                elif mode == 'STOP':
                    for items in All_outputs:
                        print('\n', items, '\n')
                    sys.exit("Service Terminated! Goodbye.")
                else:
                    print("There has been an error.")

        elif encryption == 4:
            print("Transposition")
            ciphertext = ''
            myMessage = Imgs
            # Randomises the the key number
            key = random.randrange(2, len(Imgs) - 1)
            mgs = Message(key, Message='', playfair='')
            plain = plaintextMsg(key, Message='', playfair='')
            crypt = ciphertextMsg(key, Message='', playfair='')
            while True:
                mode = str(input("Would you like to 'encrypt' or 'decrypt' or 'next' or 'STOP': "))
                if mode == 'encrypt':
                    # Calls the encryption
                    ciphertext = plain.transencryptmessage(myMessage)
                    # Print the output
                    print(ciphertext, "Encrypted!")
                    All_outputs.append(myMessage + ": " + ciphertext)
                elif mode == 'decrypt':
                    myMessage = ciphertext
                    # Calls the decryption
                    plaintext = crypt.transdecryptmessage(myMessage)
                    # Print the output
                    print(plaintext, "Decrypted!")
                    All_outputs.append(myMessage + ": " + plaintext)

                elif mode == 'next':
                    # To continue to a different cipher
                    break
                elif mode == 'STOP':
                    for items in All_outputs:
                        print('\n', items, '\n')
                    sys.exit("Service Terminated! Goodbye.")
                else:
                    print("There has been an error.")

        elif encryption == 5:
            print("Caesar")
            encrypt_text = ''
            decrypt_text = ''
            shift_number = ''
            plain = plaintextMsg(key='', Message='', playfair='')
            crypt = ciphertextMsg(key='', Message='', playfair='')
            while True:
                mode = str(input("Would you like to 'encrypt' or 'decrypt' or 'next' or 'STOP': "))
                if mode == 'encrypt':
                    # Calls the encryption
                    plain.Caesarencryption()
                    All_outputs.append(Imgs + ": " + encrypt_text + "Using:" + shift_number)
                elif mode == 'decrypt':
                    # Calls the decryption
                    crypt.Caesardecryption()
                    All_outputs.append(Imgs + ": " + decrypt_text + "Using:" + shift_number)
                elif mode == 'next':
                    # To continue to a different cipher
                    break
                elif mode == 'STOP':
                    for items in All_outputs:
                        print('\n', items, '\n')
                    sys.exit("Service Terminated! Goodbye.")
                else:
                    print("There has been an error.")

        elif encryption == 6:
            print("Playfair")
            Message('', '', "do")
            plain = plaintextMsg(key='', Message='', playfair='')
            plain.PFencrypt(Imgs)
            break

        else:
            for items in All_outputs:
                print('\n', items, '\n')
            sys.exit("Service Terminated! Goodbye.")











