import torch
import random
from .get_opcode_vector import get_asm_input_vector,str_hex_to_bytes
class Token:
    def __init__(self, name, index):
        self.name = name
        self.index = index
        self.count = 1
    def __str__(self):
        return self.name

class Tokens:
    def __init__(self, name_to_index=None, tokens=None):
        self.name_to_index = name_to_index or {}
        self.tokens = tokens or []
        self._weights = None
    def __getitem__(self, key):
        if type(key) is str:
            if self.name_to_index.get(key) is None:
                warnings.warn("Unknown token in training dataset")
                return self.tokens[self.name_to_index[""]]
            return self.tokens[self.name_to_index[key]]
        elif type(key) is int:
            return self.tokens[key]
        else:
            try:
                return [self[k] for k in key]
            except:
                raise ValueError
    def load_state_dict(self, sd):
        self.name_to_index = sd['name_to_index']
        self.tokens = sd['tokens']
    def state_dict(self):
        return {'name_to_index': self.name_to_index, 'tokens': self.tokens}
    def size(self):
        return len(self.tokens)
    def add(self, names):
        self._weights = None
        if type(names) is not list:
            names = [names]
        for name in names:
            if name not in self.name_to_index:
                token = Token(name, len(self.tokens))
                self.name_to_index[name] = token.index
                self.tokens.append(token)
            else:
                self.tokens[self.name_to_index[name]].count += 1
    def update(self, tokens_new):
        for token in tokens_new:
            if token.name not in self.name_to_index:
                token.index = len(self.tokens)
                self.name_to_index[token.name] = token.index
                self.tokens.append(token)
            else:
                self.tokens[self.name_to_index[token.name]].count += token.count
    def weights(self):
        # if no cache, calculate
        if self._weights is None:
            total = sum([token.count for token in self.tokens])
            self._weights = torch.zeros(len(self.tokens))
            for token in self.tokens:
                self._weights[token.index] = (token.count / total) ** 0.75
        return self._weights
    def sample(self, batch_size, num=5):
        return torch.multinomial(self.weights(), num * batch_size, replacement=True).view(batch_size, num)

class Function:
    def __init__(self,  meta,hexCode,hex2vec_list,fun2vec):

        self.meta = meta
        self.hexCode = hexCode
        self.hex2vec_list = hex2vec_list
        self.fun2vec=fun2vec

    @classmethod
    def load(cls, text,normal):
        '''
        gcc -S format compatiable
        '''
        meta, hexCode = {}, ""
        hexCode = text
        # print(hexCode)
        # exit()
        hex2vec_list = str_hex_to_bytes(hexCode)
        hex2vec_list, opcode_oprand_seq = get_asm_input_vector(hex2vec_list,normal)
        fun2vec = [0] * len(hex2vec_list[0])
        for i in hex2vec_list:
            for j in range(len(i)):
                fun2vec[j] += i[j]

        for i in range(len(fun2vec)):
            fun2vec[i] = fun2vec[i] / len(hex2vec_list)

        return cls(meta, hexCode, hex2vec_list, fun2vec)




    def tokens(self):
        return [token for inst in self.insts for token in inst.tokens()]

    def random_walk(self, num=3):
        return [self._random_walk() for _ in range(num)]

    def _random_walk(self):
        current, visited, seq = self.blocks[0], [], []
        while current not in visited:
            visited.append(current)
            seq += current.insts
            # no following block / hit return
            if len(current.successors) == 0 or current.insts[-1].op == 'ret':
                break
            current = random.choice(list(current.successors))
        return seq

class BasicBlock:
    def __init__(self):
        self.insts = []
        self.successors = set()
    def add(self, inst):
        self.insts.append(inst)
    def end(self):
        inst = self.insts[-1]
        return inst.is_jmp() or inst.op == 'ret'

class Instruction:
    def __init__(self, op, args):
        self.op = op
        self.args = args
    def __str__(self):
        return f'{self.op} {", ".join([str(arg) for arg in self.args if str(arg)])}'
    @classmethod
    def load(cls, text):
        text = text.strip().strip('bnd').strip() # get rid of BND prefix
        op, _, args = text.strip().partition(' ')
        if args:
            args = [arg.strip() for arg in args.split(',')]
        else:
            args = []
        args = (args + ['', ''])[:2]
        return cls(op, args)
    def tokens(self):
        return [self.op] + self.args
    def is_jmp(self):
        return 'jmp' in self.op or self.op[0] == 'j'
    def is_call(self):
        return self.op == 'call'
