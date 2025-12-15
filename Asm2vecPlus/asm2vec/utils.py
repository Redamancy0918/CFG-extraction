import os
import time
import torch
from torch.utils.data import DataLoader, Dataset
from pathlib import Path
from .datatype import Tokens, Function, Instruction
from .model import ASM2VEC
from tqdm import tqdm
class AsmDataset(Dataset):
    def __init__(self, x, y):
        self.x = x
        self.y = y
    def __len__(self):
        return len(self.x)
    def __getitem__(self, index):
        return self.x[index], self.y[index]
import csv
def csv_read(malware_num=500,benign_num=500,max_nodes=20000,min_nodes=10):

    malware_cfg_list=[]
    benign_cfg_list=[]
    with open('../CFG_data/malware_msg.csv', 'r', encoding='utf-8') as f:
    #经下述操作后，reader成为了一个可以迭代行的文件
        reader = csv.reader(f)
        #先拿出csv文件的首行（一般是基本名称说明的行），此时指针指向下一行
        header = next(reader)
        print(header)

        for row in reader:
            file_name=row[0]
            nodes_num=row[1]
            edgs_num=row[2]
            if int(nodes_num) <= max_nodes and int(nodes_num)>=min_nodes:
                malware_cfg_list.append(file_name+".gexf")
                if len(malware_cfg_list) == malware_num:
                    break

def load_data(paths, test_list=None,limit=None,normal=False):
    print("正在加载二进制函数为向量：")
    functions = []
    with open(paths, 'r', encoding='utf-8') as f:
        # 经下述操作后，reader成为了一个可以迭代行的文件
        reader = csv.reader(f)
        # 先拿出csv文件的首行（一般是基本名称说明的行），此时指针指向下一行
        header = next(reader)
        print(header)
        for row in tqdm(reader):
            func_name = row[0]
            bytes = row[1]
            try:
                fn = Function.load(bytes,normal)
            except:
                continue
            # 在函数对象列表中添加fn
            functions.append(fn)
            # print(fn)
            # exit()
            # 如果测试函数列表存在，则判断加入的函数在不在测试列表中，不在的话退出
            if test_list != None:
                if len(test_list) == len(functions):
                    break
                if func_name not in test_list:
                    continue
            if limit and len(functions) >= limit:
                break
            # 在token列表中添加函数的
            # tokens是每个函数中所有的操作符和操作数的列表
    # 返回functions的列表与对应的token列表
    return functions


#找到语境词与中心词、段向量
def preprocess2(functions):
    #上下文窗口大小
    C = 1
    #context_vec_list的每个成员由 段向量、前一条向量、后一条向量构成
    context_vec_list=[]
    center_vec_list = []
    for i, fn in enumerate(functions):
        hex2vec_list = fn.hex2vec_list
        fun2vec = fn.fun2vec
        # print("func")
        # print(fun2vec)
        # exit()
        j=C
        while True:
            center_word = hex2vec_list[j]
            center_vec_list.append(center_word)
            context_words = fun2vec + hex2vec_list[(j - C):j][0] + hex2vec_list[(j + 1):(j + C + 1)][0]
            context_vec_list.append(context_words)
            j+=1
            if j >= len(hex2vec_list)-1:
                break

    return torch.tensor(context_vec_list), torch.tensor(center_vec_list)
def preprocess(functions):
    #上下文窗口大小
    C = 1
    #context_vec_list的每个成员由 段向量、前一条向量、后一条向量构成
    context_vec_list=[]
    center_vec_list = []
    hex2vec_list_list=[]
    for i, fn in enumerate(functions):
        hex2vec_list = fn.hex2vec_list

        fun2vec = fn.fun2vec
        # print("func")
        # print(fun2vec)
        # exit()
        j=C
        while True:
            hex2vec_list_list.append(hex2vec_list)
            center_word = hex2vec_list[j]
            center_vec_list.append(center_word)


            # print(len(fun2vec))
            # print(len(hex2vec_list[(j - C):j][0]))
            # print(len(hex2vec_list[(j + 1):(j + C + 1)][0]))
            context_words = fun2vec + hex2vec_list[(j - C):j][0] + hex2vec_list[(j + 1):(j + C + 1)][0]
            context_vec_list.append(context_words)
            j+=1
            if j >= len(hex2vec_list)-1:
                break
    # print(hex2vec_list)
    # print(len(context_vec_list))
    # print(len(center_vec_list))
    # print(len(hex2vec_list_list))
    # print(context_vec_list)
    # exit()
    return torch.tensor(context_vec_list), torch.tensor(center_vec_list) , torch.tensor(hex2vec_list_list)

def train(
    functions,
    model=None,
    embedding_size=100,
    batch_size=1024,
    epochs=10,
    calc_acc=False,
    device='cuda:0',
    mode='train',
    callback=None,
    learning_rate=0.02
):
    vocab_size=len(functions[0].hex2vec_list[0])

    if mode == 'train':
        if model is None:
            model = ASM2VEC(vocab_size=vocab_size, function_size=len(functions), embedding_size=embedding_size).to(device)
        optimizer = torch.optim.Adam(model.parameters(), lr=learning_rate)
    elif mode == 'test':
        if model is None:
            raise ValueError("test mode required pretrained model")
        optimizer = torch.optim.Adam(model.linear_f.parameters(), lr=learning_rate)
    else:
        raise ValueError("Unknown mode")

    loader = DataLoader(AsmDataset(*preprocess(functions)), batch_size=batch_size, shuffle=True)

    bar =tqdm(range(epochs),position=0)
    for epoch in bar:
        start = time.time()
        loss_sum, loss_count, accs = 0.0, 0, []
        model.train()
        #inp是语境词向量，pos是中心词向量，neg是错误的中心词
        for i, (context_vec, center_vec , hex2vec_list_list) in enumerate(loader):
            loss = model(context_vec.to(device), center_vec.to(device), hex2vec_list_list.to(device))
            loss_sum, loss_count = loss_sum + loss, loss_count + 1
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()

            if i == 0 and calc_acc:
                probs = model.predict(context_vec.to(device), center_vec.to(device), hex2vec_list_list.to(device))
                accs.append(accuracy(center_vec, probs))

        if callback:
            callback({
                'model': model,
                'epoch': epoch,
                'time': time.time() - start,
                'loss': loss_sum / loss_count,
                'accuracy': torch.tensor(accs).mean() if calc_acc else None
            })
    return model

def save_model(path, model, ):
    torch.save({
        'model_params': (
            model.embeddings.num_embeddings,
            model.embeddings_f.num_embeddings,
            model.embeddings.embedding_dim
        ),
        'model': model.state_dict(),

    }, path)

def load_model(path, device='cpu'):
    checkpoint = torch.load(path, map_location=device)
    model = ASM2VEC(*checkpoint['model_params'])
    model.load_state_dict(checkpoint['model'])
    model = model.to(device)
    return model

def show_probs(x, y, probs, tokens, limit=None, pretty=False):
    if pretty:
        TL, TR, BL, BR = '┌', '┐', '└', '┘'
        LM, RM, TM, BM = '├', '┤', '┬', '┴'
        H, V = '─', '│'
        arrow = ' ➔'
    else:
        TL = TR = BL = BR = '+'
        LM = RM = TM = BM = '+'
        H, V = '-', '|'
        arrow = '->'
    top = probs.topk(5)
    for i, (xi, yi) in enumerate(zip(x, y)):
        if limit and i >= limit:
            break
        xi, yi = xi.tolist(), yi.tolist()
        print(TL + H * 42 + TR)
        print(f'{V}    {str(Instruction(tokens[xi[1]], tokens[xi[2:4]])):37} {V}')
        print(f'{V} {arrow} {str(Instruction(tokens[yi[0]], tokens[yi[1:3]])):37} {V}')
        print(f'{V}    {str(Instruction(tokens[xi[4]], tokens[xi[5:7]])):37} {V}')
        print(LM + H * 8 + TM + H * 33 + RM)
        for value, index in zip(top.values[i], top.indices[i]):
            if index in yi:
                colorbegin, colorclear = '\033[92m', '\033[0m'
            else:
                colorbegin, colorclear = '', ''
            print(f'{V} {colorbegin}{value*100:05.2f}%{colorclear} {V} {colorbegin}{tokens[index.item()].name:31}{colorclear} {V}')
        print(BL + H * 8 + BM + H * 33 + BR)

def accuracy(y, probs):
    y=y.type(torch.bool)
    return torch.mean(torch.tensor([torch.sum(probs[i][yi]) for i, yi in enumerate(y)]))

