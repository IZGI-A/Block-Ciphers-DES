from util import *
import os
import sys

class DES:
    
    ENCRYPTION = 0
    DECRYPTION = 1

    PC1 = [56, 48, 40, 32, 24, 16, 8,
           0, 57, 49, 41, 33, 25, 17,
           9, 1, 58, 50, 42, 34, 26,
           18, 10, 2, 59, 51, 43, 35,
           62, 54, 46, 38, 30, 22, 14,
           6, 61, 53, 45, 37, 29, 21,
           13, 5, 60, 52, 44, 36, 28,
           20, 12, 4, 27, 19, 11, 3
           ]

    PC2 = [
        13, 16, 10, 23, 0, 4,
        2, 27, 14, 5, 20, 9,
        22, 18, 11, 3, 25, 7,
        15, 6, 26, 19, 12, 1,
        40, 51, 30, 36, 46, 54,
        29, 39, 50, 44, 32, 47,
        43, 48, 38, 55, 33, 52,
        45, 41, 49, 35, 28, 31
    ]

    LEFT_ROTATIONS = [
        1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
    ]
    # Initial Permutation
    IP = [57, 49, 41, 33, 25, 17, 9, 1,
          59, 51, 43, 35, 27, 19, 11, 3,
          61, 53, 45, 37, 29, 21, 13, 5,
          63, 55, 47, 39, 31, 23, 15, 7,
          56, 48, 40, 32, 24, 16, 8, 0,
          58, 50, 42, 34, 26, 18, 10, 2,
          60, 52, 44, 36, 28, 20, 12, 4,
          62, 54, 46, 38, 30, 22, 14, 6
          ]

    E = [
        31, 0, 1, 2, 3, 4,
        3, 4, 5, 6, 7, 8,
        7, 8, 9, 10, 11, 12,
        11, 12, 13, 14, 15, 16,
        15, 16, 17, 18, 19, 20,
        19, 20, 21, 22, 23, 24,
        23, 24, 25, 26, 27, 28,
        27, 28, 29, 30, 31, 0
    ]

    S_BOXES = [
        # S1
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
         0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
         4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
         15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],

        # S2
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
         3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
         0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
         13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],

        # S3
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
         13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
         13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
         1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],

        # S4
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
         13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
         10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
         3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],

        # S5
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
         14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
         4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
         11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],

        # S6
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
         10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
         9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
         4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],

        # S7
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
         13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
         1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
         6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],

        # S8
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
         1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
         7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
         2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
    ]

    P = [
        15, 6, 19, 20, 28, 11,
        27, 16, 0, 14, 22, 25,
        4, 17, 30, 9, 1, 7,
        23, 13, 31, 26, 2, 8,
        18, 12, 29, 5, 21, 10,
        3, 24
    ]
    # Final Permutation
    FP = [
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25,
        32, 0, 40, 8, 48, 16, 56, 24
    ]

    def __init__(self, publicKey: bytes, IV: bytes, mode="ECB"):
        
        # Check the key and IV format
        if len(publicKey) != 8:
            raise ValueError("Invalid key size! Key should be exactly 8 bytes.")
        if len(IV) != 8:
            raise ValueError("Invalid Initial Value (IV)! Must be 8 bytes.")

        self.publicKey = publicKey
        self.IV = IV
        self.mode = mode
        self.block_size = 8

        self.L, self.R = list(), list()
        self.Kn = [[0] * 48] * 16  # 16 48-bit sub-keys
        self.final = list()

        # Initiate the subkey loop
        self.generate_subkeys()

    def generate_subkeys(self):

        publicKey = stringToBits(self.publicKey)

        parity_drop_key = permutation(publicKey, self.PC1)
        self.LK = parity_drop_key[:28]
        self.RK = parity_drop_key[28:]

        for i in range(16):
            self.LK = self.LK[self.LEFT_ROTATIONS[i]:] + self.LK[:self.LEFT_ROTATIONS[i]]
            self.RK = self.RK[self.LEFT_ROTATIONS[i]:] + self.RK[:self.LEFT_ROTATIONS[i]]

            LeftRight = self.LK + self.RK
            subkey = permutation(LeftRight, self.PC2)

            self.Kn[i] = subkey


    def s_box_substitution(self, data):
        # Implement the S-box substitution logic using the provided S-boxes

        result = []
        # Break input data into 6-bit chunks
        s_box_input = [data[i:i + 6] for i in range(0, len(data), 6)]
        # Iterate through 8 chunks
        for i in range(8):
            # Calculate row index in decimal using first and last bits
            row = (s_box_input[i][0] * 2 + s_box_input[i][-1])
            # Extract the middle 4 bits for the column index
            column = s_box_input[i][1:-1]
            column_binary = ''.join(str(bit) for bit in column)

            column = int(column_binary, 2)

            output_value = self.S_BOXES[i][row * 16 + column]

            output_bits = format(output_value, '04b')  # Convert to 4-bit binary

            result.append(output_bits)
        result = ''.join(result)
        result = [int(bit) for bit in result]

        return result

    def _chunk_crypt(self, block, crypt_type):
       
        # Apply the initial permutation using IP
        block = permutation(block, self.IP)

        # Use subkeys in reverse order for decryption
        if crypt_type == self.DECRYPTION:
            Kn = self.Kn[::-1]
        else:
            Kn = self.Kn

        # Split the block into left and right halves
        L = block[:32]
        R = block[32:]

        # Perform 16 rounds of Feistel network
        for i, subkey in enumerate(Kn):
            # Expand and permute R using E table
            expanded_R = permutation(R, self.E)

            # XOR the expanded R with the subkey
            xor_result = xor(expanded_R, subkey)

            # Apply S-box substitution
            s_box_output = self.s_box_substitution(xor_result)

            # Permute the result using P table
            permuted_result = permutation(s_box_output, self.P)

            # XOR the permuted result with the original L
            new_L = xor(L, permuted_result)

            # Swap L and R for the next round
            # L, R = R, new_L
            if i != 15:
                L = R
                R = new_L
            else:
                L = new_L
                R = R
        # Combine the final L and R
        final_block = L + R

        # Apply the final permutation using FP
        self.final = permutation(final_block, self.FP)
        return self.final

    def crypt(self, data, crypt_type):
        
       
        if len(data) % self.block_size != 0:
            if crypt_type == self.DECRYPTION:
                raise ValueError("Invalid data length. The encrypted file is corrupted.\n")
            else:
                data += (self.block_size - (len(data) % self.block_size)) * None

        if self.mode == "CBC":
            # We will need IV if the mode is CBC.
            iv = stringToBits(self.IV)

        # Split the data into blocks
        i = 0
        result = list()
        while i < len(data):
            block = stringToBits(data[i:i + 8])
            # print("BLOCK: ", len(block), block)
            # XOR with IV if the mode is CBC
            if self.mode == "CBC":
                if crypt_type == self.ENCRYPTION:
                    block = xor(block, iv)
                    cipherBlock = self._chunk_crypt(block, crypt_type)
                    iv = cipherBlock
                elif crypt_type == self.DECRYPTION:
                    cipherBlock = self._chunk_crypt(block, crypt_type)
                    cipherBlock = xor(cipherBlock, iv)
                    iv = block
                else:
                    raise ValueError("Invalid crypt_type. crypt_type should be either ENCRYPTION or DECRYPTION.")
            # If the mode is ECB
            else:
                cipherBlock = self._chunk_crypt(block, crypt_type)
            result.append(bitsToString(cipherBlock))
            i += 8
        return bytes.fromhex('').join(result)

    def encrpyt(self, data: bytearray):
        data = validateEncoding(data)
        data = padData(data, self.block_size)
        return self.crypt(data, self.ENCRYPTION)

    def decrypt(self, data: bytearray):
        data = validateEncoding(data)
        data = self.crypt(data, self.DECRYPTION)
        return unpadData(data)


def handleKey(key: str):
    key = key.encode('utf-8')
    key = key.ljust(8, b'\0')[:8]
    return key


def test(inputfile: str, publickey: str, IV: str, mode="ECB", save=True, cipher_mode="e"):
    
    publickey = handleKey(publickey)

    IV = handleKey(IV)

    cipher = DES(publickey, IV, mode=mode)
    if cipher_mode == "e":
        result = cipher.encrpyt(readBytesFromFile(inputfile))
    elif cipher_mode == "d":
        result = cipher.decrypt(readBytesFromFile(inputfile))
        result = bytearray(result)
        # result = result.decode('ascii')
    else:
        raise ValueError("Cipher mode should be 'e' for encryption, 'd' for decryption.")

    if save:
        filename = "encrypted.bin" if cipher_mode == "e" else "restored.txt"
        with open(filename, "wb") as f:
            f.write(result)
    else:
        print(result)

if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Usage: python3 DES.py <inputfile> <settingsfile> <mode> <crypt_type>")
        sys.exit(1)
    inputfile = sys.argv[1]
    settings = sys.argv[2]
    with open(settings, "r") as f:
        publickey = f.readline().strip()
        IV = f.readline().strip()
    mode = sys.argv[3]
    crypt_type = sys.argv[4]
    if crypt_type == "-encrypt":
        crypt_type = 0
    elif crypt_type == "-decrypt":
        crypt_type = 1
    else:
        print("crypt_type should be '-encrypt' for encryption, '-decrypt' for decryption.")
        sys.exit(1)

    publickey = handleKey(publickey)
    IV = handleKey(IV)

    des = DES(publickey, IV, mode=mode)

    if crypt_type == DES.ENCRYPTION:
        result = des.encrpyt(readBytesFromFile(inputfile))
    else:
        result = des.decrypt(readBytesFromFile(inputfile))
        result = bytearray(result)

    filename = "encrypted.bin" if crypt_type == 0 else "restored.txt"
    with open(filename, "wb") as f:
        f.write(result)

    # publickey = "samplekeystring"[:8]
    # IV = "initial"
    # res = test("test.txt", publickey, IV, mode="CBC", save=True)
    # dec = test("encrypted.bin", publickey, IV, mode="CBC", cipher_mode="d", save=False)
