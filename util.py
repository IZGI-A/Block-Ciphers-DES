
def validateEncoding(data):
    # Only accept byte strings or ascii unicode values, otherwise
    # there is no way to correctly decode the data into bytes.
    if isinstance(data, str):
        # Only accept ascii unicode values.
        try:
            return data.encode('ascii')
        except UnicodeEncodeError:
            pass
        raise ValueError("Can only work with encoded strings, not Unicode.")
    return data


def readBytesFromFile(filename):
    with open(filename, "rb") as f:
        return bytearray(f.read())


def permutation(block, table):
    """
    Permutate the given data block with the given permutation table.
    """
    return list(map(lambda x: block[x], table))


def xor(a, b):
    return list(map(lambda x, y: x ^ y, a, b))


def stringToBits(data):
    """
    Transforms a list of bytes into a list of bits.
    """
    N = len(data) * 8
    result = [0] * N
    pos = 0
    for ch in data:
        i = 7
        while i >= 0:
            if ch & (1 << i) != 0:
                result[pos] = 1
            else:
                result[pos] = 0
            pos += 1
            i -= 1
    return result


def bitsToString(data):
    """
    Transforms a list of bits into a list of bytes.
    """
    result = list()
    pos, c = 0, 0
    while pos < len(data):
        c += data[pos] << (7 - (pos % 8))
        if (pos % 8) == 7:
            result.append(c)
            c = 0
        pos += 1
    return bytes(result)


def padData(data, block_size):
    """
    Inserts padding to given data by the block size. Outputs padded data.
    """
    pad_len = 8 - (len(data) % block_size)
    data += bytes([pad_len] * pad_len)
    return data


def unpadData(data):
    """
    Removes padding if there is any.
    """
    pad_len = data[-1]
    data = data[:-pad_len]
    return data
