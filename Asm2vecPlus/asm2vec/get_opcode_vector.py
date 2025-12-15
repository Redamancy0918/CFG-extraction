#!/usr/bin/env python

# Capstone Python bindings, by Nguyen Anh Quynnh <aquynh@gmail.com>
from __future__ import print_function
from capstone import *
from capstone.x86 import *
from .xprint import to_hex, to_x, to_x_32
import lief
import base64
import os
import random
import numpy as np




def softmax(x):
    x_exp = np.exp(x)
    # 如果是列向量，则axis=0
    x_sum = np.sum(x_exp, axis=0, keepdims=True)
    s = x_exp / x_sum
    return s


legacy_prefix_all_msg={"lock":[0x0,0xF0],"segment":[0x2E,0x36,0x3E,0x26,0x64,0x65],"oprandsize":[0x0,0x66],"address":[0x0,0x67]}

# X86_CODE64 = b"\x55\x48\x8b\x05\xb8\x13\x00\x00\xe9\xea\xbe\xad\xde\xff\x25\x23\x01\x00\x00\xe8\xdf\xbe\xad\xde\x74\xff"
# X86_CODE16 = b"\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00\x05\x23\x01\x00\x00\x36\x8b\x84\x91\x23\x01\x00\x00\x41\x8d\x84\x39\x89\x67\x00\x00\x8d\x87\x89\x67\x00\x00\xb4\xc6\x66\xe9\xb8\x00\x00\x00\x67\xff\xa0\x23\x01\x00\x00\x66\xe8\xcb\x00\x00\x00\x74\xfc"
# X86_CODE32 = b"\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00\x05\x23\x01\x00\x00\x36\x8b\x84\x91\x23\x01\x00\x00\x41\x8d\x84\x39\x89\x67\x00\x00\x8d\x87\x89\x67\x00\x00\xb4\xc6\xe9\xea\xbe\xad\xde\xff\xa0\x23\x01\x00\x00\xe8\xdf\xbe\xad\xde\x74\xff"

#记录有效性错误的程序总数
error_validity_sum=0
#验证程序的有效性，暂时先只用32位未加密程序做测试
def check_validity(binary):
    global error_validity_sum
    #是否加壳标志
    shell_flag=1

    try:
        text = binary.get_section(".text")
    except Exception as e:
        if "No such section with this name" in str(e):
            text = binary.get_section("CODE")
        else:
            shell_flag=0

    if shell_flag==0:
        print("程序可能加壳")
        error_validity_sum+=1
        return False

    if "CHARA_32BIT_MACHINE" not in str(binary.header):
        print("不是一个32位程序")
        error_validity_sum+=1
        return False
    return True

def str_hex_to_bytes(str_hex):
    # print(str_hex)
    # exit()
    y = bytearray.fromhex(str_hex)
    z = list(y)
    # print(z)

    asm_hex_str = b''

    # test_content = [0x26, 0x66, 0x67, 0xF0, 0x81, 0x84, 0xC8, 0x44, 0x33, 0x22, 0x11, 0x78, 0x56, 0x34, 0x12]
    #normal
    for i in z:
        # for i in test_content:
        right = str(hex(i))[2:]

        if right == "0":
            right = "00"
        if len(right) == 1:
            right = "0" + right
        item = base64.b16decode(right.upper())
        asm_hex_str += item

    # print(asm_hex_str)
    return asm_hex_str

def get_asm_text_code(file_name):
    binary = lief.parse(file_name)


    if check_validity(binary)==True:
        try:
            text = binary.get_section(".text")
        except Exception as e:
            text = binary.get_section("CODE")


        # print(text.content)
        # exit()

        asm_hex_str=b''

        # test_content = [0x26, 0x66, 0x67, 0xF0, 0x81, 0x84, 0xC8, 0x44, 0x33, 0x22, 0x11, 0x78, 0x56, 0x34, 0x12]
        for i in text.content:
        # for i in test_content:
            right=str(hex(i))[2:]

            if right=="0":
                right="00"
            if len(right)==1:
                right="0"+right
            item =base64.b16decode(right.upper())
            asm_hex_str+=item

        return True,asm_hex_str
    else:
        return False,""

# X86_CODE32 = get_asm_text_code("./TEST")



# all_tests = (
#     # (CS_ARCH_X86, CS_MODE_16, X86_CODE16, "X86 16bit (Intel syntax)", None),
#     # (CS_ARCH_X86, CS_MODE_32, X86_CODE32, "X86 32 (AT&T syntax)", CS_OPT_SYNTAX_ATT),
#     (CS_ARCH_X86, CS_MODE_32, X86_CODE32, "X86 32 (Intel syntax)", None),
#     # (CS_ARCH_X86, CS_MODE_64, X86_CODE64, "X86 64 (Intel syntax)", None),
# )


def get_eflag_name(eflag):
    if eflag == X86_EFLAGS_UNDEFINED_OF:
        return "UNDEF_OF"
    elif eflag == X86_EFLAGS_UNDEFINED_SF:
        return "UNDEF_SF"
    elif eflag == X86_EFLAGS_UNDEFINED_ZF:
        return "UNDEF_ZF"
    elif eflag == X86_EFLAGS_MODIFY_AF:
        return "MOD_AF"
    elif eflag == X86_EFLAGS_UNDEFINED_PF:
        return "UNDEF_PF"
    elif eflag == X86_EFLAGS_MODIFY_CF:
        return "MOD_CF"
    elif eflag == X86_EFLAGS_MODIFY_SF:
        return "MOD_SF"
    elif eflag == X86_EFLAGS_MODIFY_ZF:
        return "MOD_ZF"
    elif eflag == X86_EFLAGS_UNDEFINED_AF:
        return "UNDEF_AF"
    elif eflag == X86_EFLAGS_MODIFY_PF:
        return "MOD_PF"
    elif eflag == X86_EFLAGS_UNDEFINED_CF:
        return "UNDEF_CF"
    elif eflag == X86_EFLAGS_MODIFY_OF:
        return "MOD_OF"
    elif eflag == X86_EFLAGS_RESET_OF:
        return "RESET_OF"
    elif eflag == X86_EFLAGS_RESET_CF:
        return "RESET_CF"
    elif eflag == X86_EFLAGS_RESET_DF:
        return "RESET_DF"
    elif eflag == X86_EFLAGS_RESET_IF:
        return "RESET_IF"
    elif eflag == X86_EFLAGS_TEST_OF:
        return "TEST_OF"
    elif eflag == X86_EFLAGS_TEST_SF:
        return "TEST_SF"
    elif eflag == X86_EFLAGS_TEST_ZF:
        return "TEST_ZF"
    elif eflag == X86_EFLAGS_TEST_PF:
        return "TEST_PF"
    elif eflag == X86_EFLAGS_TEST_CF:
        return "TEST_CF"
    elif eflag == X86_EFLAGS_RESET_SF:
        return "RESET_SF"
    elif eflag == X86_EFLAGS_RESET_AF:
        return "RESET_AF"
    elif eflag == X86_EFLAGS_RESET_TF:
        return "RESET_TF"
    elif eflag == X86_EFLAGS_RESET_NT:
        return "RESET_NT"
    elif eflag == X86_EFLAGS_PRIOR_OF:
        return "PRIOR_OF"
    elif eflag == X86_EFLAGS_PRIOR_SF:
        return "PRIOR_SF"
    elif eflag == X86_EFLAGS_PRIOR_ZF:
        return "PRIOR_ZF"
    elif eflag == X86_EFLAGS_PRIOR_AF:
        return "PRIOR_AF"
    elif eflag == X86_EFLAGS_PRIOR_PF:
        return "PRIOR_PF"
    elif eflag == X86_EFLAGS_PRIOR_CF:
        return "PRIOR_CF"
    elif eflag == X86_EFLAGS_PRIOR_TF:
        return "PRIOR_TF"
    elif eflag == X86_EFLAGS_PRIOR_IF:
        return "PRIOR_IF"
    elif eflag == X86_EFLAGS_PRIOR_DF:
        return "PRIOR_DF"
    elif eflag == X86_EFLAGS_TEST_NT:
        return "TEST_NT"
    elif eflag == X86_EFLAGS_TEST_DF:
        return "TEST_DF"
    elif eflag == X86_EFLAGS_RESET_PF:
        return "RESET_PF"
    elif eflag == X86_EFLAGS_PRIOR_NT:
        return "PRIOR_NT"
    elif eflag == X86_EFLAGS_MODIFY_TF:
        return "MOD_TF"
    elif eflag == X86_EFLAGS_MODIFY_IF:
        return "MOD_IF"
    elif eflag == X86_EFLAGS_MODIFY_DF:
        return "MOD_DF"
    elif eflag == X86_EFLAGS_MODIFY_NT:
        return "MOD_NT"
    elif eflag == X86_EFLAGS_MODIFY_RF:
        return "MOD_RF"
    elif eflag == X86_EFLAGS_SET_CF:
        return "SET_CF"
    elif eflag == X86_EFLAGS_SET_DF:
        return "SET_DF"
    elif eflag == X86_EFLAGS_SET_IF:
        return "SET_IF"
    else:
        return None

def vector_to_asm(res_vector):
    test_vector=[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

    test_vector=[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

    addr_vec=test_vector[:64]
    opcode_vec=test_vector[64:(64+256)]
    option_vec=test_vector[(64+256):(64+256+5)]
    prefix_vec=test_vector[(64+256+5):(64+256+5+9)]
    modrm_vec=test_vector[(64+256+5+9):(64+256+5+9+20)]
    sib_vec=test_vector[(64+256+5+9+20):(64+256+5+9+20+20)]
    disp_flag=test_vector[(64+256+5+9+20+20):(64+256+5+9+20+20+1)]
    disp_vec=test_vector[(64+256+5+9+20+20+1):(64+256+5+9+20+20+64)]
    imme_flag=test_vector[(64+256+5+9+20+20+1+64):(64+256+5+9+20+20+1+64+1)]
    imme_vec=test_vector[(64+256+5+9+20+20+1+64+1):]

    # print("\taddr_vec : "+ str(addr_vec))
    # print("\topcode_vec : " + str(opcode_vec))
    # print("\toption_vec : " + str(option_vec))
    # print("\tprefix_vec : " + str(prefix_vec))
    # print("\tmodrm_vec : " + str(modrm_vec))
    # print("\tsib_vec : " + str(sib_vec))
    # print("\tdisp_flag : " + str(disp_flag))
    # print("\tdisp_vec : " + str(disp_vec))
    # print("\timme_flag : " + str(imme_flag))
    # print("\timme_vec : " + str(imme_vec))

    addr="0b"
    opcode=0
    # option="0b"
    prefix=[0,0,0,0]
    modrm="0b"
    sib="0b"
    disp_flag_str="0b"
    disp="0b"
    imme_flag_str="0b"
    imme="0b"

    for i in addr_vec:
        addr+=str(i)
    for i in range(len(opcode_vec)):
        if opcode_vec[i]==1:
            opcode=i

    if prefix_vec[0]==1:
        prefix[0]=0xF0

    prefix_vec_2=prefix_vec[1:7]
    for i in range(len(prefix_vec_2)):
        if prefix_vec_2[i]==1:
            prefix[1]=legacy_prefix_all_msg[i]

    if prefix_vec[7]==1:
        prefix[2]=0x66
    if prefix_vec[8]==1:
        prefix[3]=0x67

    modrm1=0
    modrm2=0
    modrm3=0
    modrm_vec1=modrm_vec[:4]
    for i in range(len(modrm_vec1)):
        if modrm_vec1[i]==1:
            modrm1=i
    modrm_vec2 = modrm_vec[4:12]
    for i in range(len(modrm_vec2)):
        if modrm_vec2[i] == 1:
            modrm2 = i
    modrm_vec3 = modrm_vec[12:]
    for i in range(len(modrm_vec3)):
        if modrm_vec3[i] == 1:
            modrm3 = i

    modrm1,modrm2,modrm3=bin(modrm1),bin(modrm2),bin(modrm3)
    modrm1, modrm2, modrm3 = modrm1[2:],modrm2[2:],modrm3[2:]
    modrm ="0b"+modrm1+modrm2+modrm3


    sib1 = 0
    sib2 = 0
    sib3 = 0
    sib_vec1 = sib_vec[:4]
    for i in range(len(sib_vec1)):
        if sib_vec1[i] == 1:
            sib1 = i
    sib_vec2 = sib_vec[4:12]
    for i in range(len(sib_vec2)):
        if sib_vec2[i] == 1:
            sib2 = i
    sib_vec3 = sib_vec[12:]
    for i in range(len(sib_vec3)):
        if sib_vec3[i] == 1:
            sib3 = i

    sib1, sib2, sib3 = bin(sib1), bin(sib2), bin(sib3)
    sib1, sib2, sib3 = sib1[2:], sib2[2:], sib3[2:]
    sib = "0b"+sib1 + sib2 + sib3

    # print()
    # print("\taddr : " + str(hex(int(addr,2))))
    # print("\topcode : " + str(opcode))
    # print("\tmodrm : " + str(modrm))
    # print("\tsib : " + str(sib))
    pass

def msg_to_vector(normal,address,prefix,opcode,modrm,sib,disp,imme,imme_cont):

    # addr_vec=[0]*64
    opcode_vec=[0]*256
    # option_vec=[0]*8 #prefix[0,0,0,0]\modrm\sib\disp\imme
    option_vec = [0] * 5  # prefix[0,0,0,0]\modrm\sib\disp\imme
    prefix_vec=[0]*9  #1/6/1/1
    moderm_vec=[0]*20
    sib_vec=[0]*20
    # disp_flag=[0]
    disp_vec=[0]*32
    # imme_flag=[0]
    imme_vec=[0]*32
    address, opcode, modrm, sib, disp, imme=int(address),int(opcode),int(modrm),int(sib),int(disp),int(imme)
    address, modrm, sib, disp, imme= bin(address), bin(modrm), bin(sib), bin(disp), bin(imme)

    if disp[0]=="-":
        disp_flag=[1]
        disp=disp[1:]
    if imme[0]=="-":
        imme_flag=[1]
        imme=disp[1:]
    address, modrm, sib, disp, imme= address[2:], modrm[2:], sib[2:], disp[2:], imme[2:]

    #填充address至64位
    # if len(address)<64:
    #     address="0"*(64-len(address))+address
    #
    # for i in range(len(address)):
    #     addr_vec[i]=int(address[i])
    # print("addr_vec:"+str(addr_vec))

    #one-hot表示
    opcode_vec[opcode]=1


    if prefix[0]!=0 :
        option_vec[0]=1
    if prefix[1]!=0 :
        option_vec[0] = 1
    if prefix[2]!=0 :
        option_vec[0] = 1
    if prefix[3]!=0:
        option_vec[0] = 1

    if modrm!="0":
        option_vec[1]=1
    if sib!="0":
        option_vec[2]=1
    if disp!="0":
        option_vec[3]=1
    if imme_cont!=0:
        option_vec[4]=1

    if len(disp)>32:
        disp=disp[:32]

    if len(imme)>32:
        imme = imme[:32]

    if len(disp)<=32:
        disp="0"*(32-len(disp))+disp

    if len(imme)<=32:
        imme="0"*(32-len(imme))+imme

    for i in range(len(disp)):
        disp_vec[i] = int(disp[i])


    for i in range(len(imme)):
        imme_vec[i] = int(imme[i])
    # print("0x%x:\t%s\t%s" % (insn.address, insn.mnemonic, insn.op_str))
    # print("\t机器码 : "+ str(asm_code))

    for i in range(len(prefix)):
        prefix[i]=int(prefix[i])

    for j in range(len(legacy_prefix_all_msg["lock"])):
        if prefix[0]==legacy_prefix_all_msg["lock"][j]:
            prefix_vec[0]=j
            break
    for j in range(len(legacy_prefix_all_msg["segment"])):
        if prefix[1] == legacy_prefix_all_msg["segment"][j]:
            prefix_vec[j+1] = 1
            break

    for j in range(len(legacy_prefix_all_msg["oprandsize"])):
        if prefix[2] == legacy_prefix_all_msg["oprandsize"][j]:
            prefix_vec[7] = j
            break
    for j in range(len(legacy_prefix_all_msg["address"])):
        if prefix[3] == legacy_prefix_all_msg["address"][j]:
            prefix_vec[8] = j
            break

    # print("prefix_vec:" + str(prefix_vec))


    if len(modrm)<8:
        modrm="0"*(8-len(modrm))+modrm
    # print("modrm:"+modrm)
    modrm_split1="0b"+modrm[:2]
    modrm_split2="0b"+modrm[2:5]
    modrm_split3="0b"+modrm[5:]
    modrm_int1 = int(modrm_split1,2)
    modrm_int2 = int(modrm_split2, 2)
    modrm_int3 = int(modrm_split3, 2)

    moderm_vec[modrm_int1] = 1
    moderm_vec[modrm_int2 + 4] = 1
    moderm_vec[modrm_int3 + 12] = 1

    if len(sib)<8:
        sib="0"*(8-len(sib))+sib
    # print("sib:"+sib)
    sib_split1="0b"+sib[:2]
    sib_split2="0b"+sib[2:5]
    sib_split3="0b"+sib[5:]
    sib_int1 = int(sib_split1,2)
    sib_int2 = int(sib_split2, 2)
    sib_int3 = int(sib_split3, 2)

    sib_vec[sib_int1] = 1
    sib_vec[sib_int2 + 4] = 1
    sib_vec[sib_int3 + 12] = 1

    # result_vec = opcode_vec + option_vec + prefix_vec + moderm_vec + sib_vec + disp_flag + disp_vec + imme_flag + imme_vec
    # result_vec=addr_vec+opcode_vec+option_vec+prefix_vec+moderm_vec+sib_vec+disp_flag+disp_vec+imme_flag+imme_vec
    result_vec=opcode_vec+option_vec+prefix_vec+moderm_vec+sib_vec+disp_vec+imme_vec
    # print("addr_vec:"+str(addr_vec))
    # print("opcode_vec:" + str(opcode_vec))
    # print("option_vec:"+str(option_vec))
    # print("disp_vec:"+str(disp_vec))
    # print("imme_vec:"+str(imme_vec))
    # print("prefix_vec:" + str(prefix_vec))
    # print("moderm_vec:" + str(moderm_vec))
    # print("sib_vec:" + str(sib_vec))
    # print("result_vec:\n"+str(result_vec))


    #对数组做归一化处理
    # if normal==True:
    #     not_zero_sum=0
    #     for i in result_vec:
    #         if i != 0:
    #             not_zero_sum+=i
    #     for i in range(len(result_vec)):
    #         if result_vec[i] != 0:
    #             result_vec[i]=result_vec[i]/not_zero_sum
    return result_vec




# opcode_list = []
def get_asm_msg(insn):
    # print(dir(insn))
    # exit()
    text1=""
    for i in range(insn.size):
        text1 += '%02X ' % insn.bytes[i]
    address=insn.address

    prefix=insn.prefix
    opcode=insn.opcode

    modrm=insn.modrm
    disp=insn.disp
    sib=insn.sib
    imme_cont=insn.op_count(X86_OP_IMM)

    if imme_cont!=0:
        op = insn.op_find(X86_OP_IMM, 1)
        imme="0x"+to_x(op.imm)
        imme=int(imme,16)
    else:
        imme=0

    # if prefix!=[0,0,0,0]:

    # print("\t%s" % (insn.mnemonic))
    # print("\t%s\t%s" % (insn.mnemonic, insn.op_str))
    # print(dir(insn.op_count))

    # print("\t机器码 : "+ str(asm_code))
    # print("\t地址addr : "+ str(address))
    # print("\t前缀prefix ：" + str(prefix))
    # print("\t操作码opcode : "+str(opcode))
    # print("\tmodrm : "+str(modrm))
    # print("\tsib : "+str(sib))
    # print(type(insn.disp))
    # print("\tdisp : "+hex(insn.disp))
    # print("\timme : "+hex(imme))
    # exit()

    # 打印操作数的REX前缀（非零值与x86_64指令相关）
    # print("\trex: 0x%x" % (insn.rex))
    return str(address),prefix,str(opcode[0]),str(modrm),str(sib),str(disp),str(imme),imme_cont

def get_asm_msg2(insn):
    # print(dir(insn))
    # exit()
    text1=""
    for i in range(insn.size):
        text1 += '%02X ' % insn.bytes[i]
    address=insn.address

    prefix=insn.prefix
    opcode=insn.opcode

    modrm=insn.modrm
    disp=insn.disp
    sib=insn.sib
    imme_cont=insn.op_count(X86_OP_IMM)

    if imme_cont!=0:
        op = insn.op_find(X86_OP_IMM, 1)
        imme="0x"+to_x(op.imm)
        imme=int(imme,16)
    else:
        imme=0

    # if prefix!=[0,0,0,0]:

    # print("\t%s" % (insn.mnemonic))

    # print(dir(insn.op_count))

    # print("\t机器码 : "+ str(asm_code))
    # print("\t地址addr : "+ str(address))
    # print("\t前缀prefix ：" + str(prefix))
    # print("\t操作码opcode : "+str(opcode))
    # print("\tmodrm : "+str(modrm))
    # print("\tsib : "+str(sib))
    # print(type(insn.disp))
    # print("\tdisp : "+hex(insn.disp))
    # print("\timme : "+hex(imme))
    op_str=insn.op_str.replace("0x","ox")
    if insn.disp<10:
        disp=str(insn.disp)
    else:
        disp=hex(insn.disp)

    if imme<10:
        imme2=str(imme)
    else:
        imme2=hex(imme).replace("0x","ox")

    r_list=["r1","r2","r3","r4","r5","r6""r7","r8","r9","r10","r11","r12""r13","r14","r15"]
    print("\t%s\t%s" % (insn.mnemonic, insn.op_str))
    #替换为CONST
    if disp in op_str:
        flag=0
        for i in r_list:
            if i in op_str:
                flag=1
                break
        if flag==1:
            op_str=op_str.replace(" "+disp," CONST")
        else:
            op_str = op_str.replace(disp, "CONST")

    if imme2 in op_str:
        flag = 0
        for i in r_list:
            if i in op_str:
                flag = 1
                break
        if flag == 1:
            op_str = op_str.replace(" " + imme2, " CONST")
        else:
            op_str = op_str.replace(imme2, "CONST")
    print("\t%s\t%s" % (insn.mnemonic, op_str))

    # exit()
    # exit()

    # 打印操作数的REX前缀（非零值与x86_64指令相关）
    # print("\trex: 0x%x" % (insn.rex))
    return str(address),prefix,str(opcode[0]),str(modrm),str(sib),str(disp),str(imme),imme_cont

def get_asm_input_vector(X86_CODE32,normal=False):

    arch, mode, code, comment, syntax=CS_ARCH_X86, CS_MODE_32, X86_CODE32, "X86 32 (Intel syntax)", None
    one_sample_vec_seq=[]
    opcode_oprand_seq=[]
    try:

        md = Cs(arch, mode)
        md.detail = True
        if syntax is not None:
            md.syntax = syntax

        for insn in md.disasm(code, 0x0):

            address, prefix, opcode, modrm, sib, disp, imme,imme_cont=get_asm_msg( insn)
            result_vec=msg_to_vector(normal,address, prefix, opcode, modrm, sib, disp, imme,imme_cont)
            one_sample_vec_seq.append(result_vec)
            opcode_oprand_seq.append("0x%x:%s %s" % (insn.address, insn.mnemonic, insn.op_str))
            # print("one_sample_vec_seq:" + str(one_sample_vec_seq))
            # print(len(one_sample_vec_seq))
        #返回vector列表，

        return one_sample_vec_seq,opcode_oprand_seq
    except CsError as e:
        print("ERROR: %s" % e)
        exit()

#随机获取50条指令，以及对应的vector
def get_random_asm_seq(seq_num,one_sample_vec_seq,opcode_oprand_seq):

    one_sample_vec_seq=random.sample(one_sample_vec_seq,seq_num)
    opcode_oprand_seq=random.sample(opcode_oprand_seq,seq_num)
    # print(one_sample_vec_seq)
    # print(opcode_oprand_seq)
    return one_sample_vec_seq,opcode_oprand_seq
    # pass



def get_vec_seq():
    file_dir = "E:\Data\Data_\malware"
    file_list = sorted(os.listdir(file_dir))
    # print(file_list)
    sample_vec_seq=[]
    # 对文件夹中每一个文件进行遍历
    for item_file in file_list:
        # item_file="msvcrt20.dll"
        item_file="e3d5f6b7189fc7fb5904943f24fb749ccd70c6d2b5b9b3892525a1188310f80a"
        # item_file="efa4f015dc1b81d9dedd130439dea9f9cc2e5d2451e9bd1186990973cf14b693"
        # print(item_file)
        bool_flag, X86_CODE32 = get_asm_text_code(os.path.join(file_dir, item_file))
        # print(X86_CODE32)
        # exit()
        #如果当前程序不是32位程序或者有加壳，则跳过
        if bool_flag == False:
            continue

        one_sample_vec_seq,opcode_oprand_seq = get_asm_input_vector(X86_CODE32)
        # sample_vec_seq.append(one_sample_vec_seq)
        break

    return one_sample_vec_seq,opcode_oprand_seq

# if __name__ == '__main__':
#     get_asm_input_vector("6a09e8c5fdffff83c404ff742404e89efeffff83c4046a09e80bf3ffff83c404c3",normal=True)
    # one_sample_vec_seq, opcode_oprand_seq=get_random_asm_seq()
    # print(len(one_sample_vec_seq))
    # print(len(opcode_oprand_seq))
    # exit()
    # sample_vec_seq=get_vec_seq()
    # print("有效性错误程序总数："+str(error_validity_sum))
    # print(sample_vec_seq)
    # print(len(sample_vec_seq[0]))
