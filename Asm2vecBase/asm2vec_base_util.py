import sys
# sys.path.append("/features_method/asm2vec_plus/")
from capstone import *
from capstone.x86 import *
import torch
import base64
from asm2vec_base_model import ASM2VEC
from xprint import to_hex, to_x, to_x_32

def load_asm2vec_base_model(path, device='cpu'):
    checkpoint = torch.load(path, map_location=device)

    model = ASM2VEC(*checkpoint['model_params'])
    model.load_state_dict(checkpoint['model'])
    model = model.to(device)
    return model

def str_hex_to_bytes(str_hex):

    y = bytearray.fromhex(str_hex)
    z = list(y)
    asm_hex_str = b''

    for i in z:

        right = str(hex(i))[2:]
        if right == "0":
            right = "00"
        if len(right) == 1:
            right = "0" + right
        item = base64.b16decode(right.upper())
        asm_hex_str += item
    return asm_hex_str



import re#导入包
def get_asm_msg(insn):
    # print(dir(insn))
    # exit()
    text1=""
    for i in range(insn.size):
        text1 += '%02X ' % insn.bytes[i]

    imme_cont=insn.op_count(X86_OP_IMM)

    if imme_cont!=0:
        op = insn.op_find(X86_OP_IMM, 1)
        imme="0x"+to_x(op.imm)
        imme=int(imme,16)
    else:
        imme=0
    # print(insn.op_str)


    op_str=insn.op_str
    #查找为0x开头的16进制数
    hex_list1=re.findall(pattern=r'\b0x[0-9a-fA-F]+\b', string=op_str)
    for i in hex_list1:
        op_str=op_str.replace(i,"CONST")
    #查找十六进制数字。
    hex_list2=re.findall(pattern=r'\b[0-9a-fA-F]+\b', string=op_str)
    for i in hex_list2:
        op_str=op_str.replace(i,"CONST")

    # 打印操作数的REX前缀（非零值与x86_64指令相关）
    # print("\trex: 0x%x" % (insn.rex))
    return insn.mnemonic,op_str

import json
def msg_to_vector(normal,mnemonic,op_str):
    with open("./Asm2vecBase/" + 'vocab.json', 'r', encoding='utf-8') as fp:
        asm2vec_vocab = json.load(fp)

    vec_len=372
    mnemonic_vec=[0]*int(vec_len/2)
    op_str_vec1=[0]*int(vec_len/2)
    op_str_vec2= [0] * int(vec_len / 2)
    mean_list = [0] * int(vec_len / 2)

    op_str_list=op_str.split(",")
    # print(op_str_list)
    # flag_1=0
    # if op_str:
    #     flag_1=1

    flag_2=0
    if len(op_str_list)!=2:
        op_str_1=op_str_list[0]
        op_str_2=""
    else:
        flag_2=1
        op_str_1 = op_str_list[0]
        op_str_2 = op_str_list[1].lstrip()



    # print(mnemonic)
    # print(op_str_list)
    # print(op_str_1)
    # print(op_str_2)
    #操作符在vocab里的位置
    # print("---")
    if mnemonic in asm2vec_vocab:
        mn_index=asm2vec_vocab[mnemonic]
        if mn_index< int(vec_len / 2):
            mnemonic_vec[mn_index]=1

    if op_str_1 in asm2vec_vocab:
        op_str_1_index=asm2vec_vocab[op_str_1]
        if op_str_1_index < int(vec_len / 2):
            op_str_vec1[op_str_1_index] = 1

    if op_str_2 in asm2vec_vocab:
        op_str_2_index=asm2vec_vocab[op_str_2]
        if op_str_2_index < int(vec_len / 2):
            op_str_vec2[op_str_2_index] = 1

    for i in range(len(op_str_vec1)):

        mean_list[i]=(op_str_vec1[i]+op_str_vec2[i])/2

    # print(mnemonic_vec)
    # print(op_str_vec1)
    # print(mean_list)
    #如果只有一个操作数

    if flag_2==0:
        mnemonic_vec.extend(op_str_vec1)
    else:

        mnemonic_vec.extend(mean_list)

    result_vec=mnemonic_vec
    # print(result_vec)
    # exit()
    #对数组做归一化处理
    if normal==True:
        not_zero_sum=0
        for i in result_vec:
            if i != 0:
                not_zero_sum+=i
        for i in range(len(result_vec)):
            if result_vec[i] != 0:
                result_vec[i]=result_vec[i]/not_zero_sum
    return result_vec

def get_asm_input_vector(X86_CODE32,normal=True):

    arch, mode, code, comment, syntax=CS_ARCH_X86, CS_MODE_32, X86_CODE32, "X86 32 (Intel syntax)", None
    one_sample_vec_seq=[]
    opcode_oprand_seq=[]
    try:

        md = Cs(arch, mode)
        md.detail = True
        if syntax is not None:
            md.syntax = syntax

        for insn in md.disasm(code, 0x0):

            mnemonic,op_str=get_asm_msg( insn)
            result_vec=msg_to_vector(normal,mnemonic,op_str)
            one_sample_vec_seq.append(result_vec)
            opcode_oprand_seq.append("0x%x:%s %s" % (insn.address, insn.mnemonic, insn.op_str))
            # print("one_sample_vec_seq:" + str(one_sample_vec_seq))
            # print(len(one_sample_vec_seq))
        #返回vector列表，

        return one_sample_vec_seq,opcode_oprand_seq
    except CsError as e:
        print("ERROR: %s" % e)
        exit()