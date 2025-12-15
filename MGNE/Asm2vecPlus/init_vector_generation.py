from asm2vec.get_opcode_vector import get_asm_input_vector,str_hex_to_bytes
from capstone import *
import binascii

def asm2vec_plus1(hex_asm):
    hex2vec_list=[]
    for hex_asm_item in hex_asm[:10000]:
        hex2vec = str_hex_to_bytes(hex_asm_item)
        hex2vec, opcode_oprand_seq = get_asm_input_vector(hex2vec)
        # 开始对每一行的代码求平均值，得到函数的vec
        # hex2vec_list.append(hex2vec[0])
        # print(len(hex2vec[0]))
        # exit()
        hex2vec_list.append(hex2vec[0])
        # str(asm_init_vec_list).replace(" ", "")
    return hex2vec_list

def asm2vec_plus(hex_asm):
    hex2vec_list=[]
    for hex_asm_item in hex_asm[:10000]:
        hex2vec = str_hex_to_bytes(hex_asm_item)
        hex2vec, opcode_oprand_seq = get_asm_input_vector(hex2vec)
        # 开始对每一行的代码求平均值，得到函数的vec
        # hex2vec_list.append(hex2vec[0])
        # print(len(hex2vec[0]))
        # exit()
        hex2vec_list.append(hex2vec[0])
        # str(asm_init_vec_list).replace(" ", "")
    return str(hex2vec_list).replace(" ", "")

def asm_to_init_vec(asm_codes):
    asm_init_vec_list=[]
    # for codes in asm_codes:
    codes_list=asm_codes.split(",")

    for code in codes_list:
        hex2vec_list = str_hex_to_bytes(code)
        hex2vec_list, opcode_oprand_seq = get_asm_input_vector(hex2vec_list)
        asm_init_vec_list.append(hex2vec_list[0])

    return asm_init_vec_list

def get_seq_encoder(basicblock_hex="e890030000e890030000"):
    code_list = []
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    HexCode = binascii.unhexlify(basicblock_hex)
    for item in md.disasm(HexCode, 0):
        hex_string = ''.join(['{:02x}'.format(b) for b in item.bytes])
        code_list.append(hex_string)
    # print(code_list)

    return asm2vec_plus(code_list)

def get_seq_encoder1(basicblock_hex="e890030000e890030000"):
    code_list = []
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    HexCode = binascii.unhexlify(basicblock_hex)
    for item in md.disasm(HexCode, 0):
        hex_string = ''.join(['{:02x}'.format(b) for b in item.bytes])
        code_list.append(hex_string)
    # print(code_list)

    return asm2vec_plus1(code_list)

# asm_init_vec_list = asm_to_init_vec("e890030000")
# print(asm_init_vec_list)

# asm_init_vec_list = asm2vec_plus(["e890030000","e890030000"])
# print(asm_init_vec_list)

# asm_init_vec_list = str(asm_init_vec_list).replace(" ", "")
# print(asm_init_vec_list)
if __name__ == '__main__':
    pass