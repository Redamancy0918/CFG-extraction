import torch
import torch.nn as nn
import torch.nn.functional as F

bce, sigmoid, softmax = nn.BCELoss(), nn.Sigmoid(), nn.Softmax(dim=1)

class ASM2VEC(nn.Module):
    def __init__(self, vocab_size, function_size, embedding_size):
        super(ASM2VEC, self).__init__()

        # self.lstm = nn.LSTM(hidden_dim, hidden_dim, batch_first=True)

        self.linear_f=nn.Linear(vocab_size,embedding_size, bias=True)

        self.linear_context= nn.Linear(vocab_size, embedding_size, bias=True)

        # self.linear_next = nn.Linear(vocab_size, embedding_size, bias=True)
        self.linear_output = nn.Linear(embedding_size,vocab_size, bias=True)

        #生成token的映射向量
        self.embeddings = nn.Embedding(vocab_size, embedding_size, _weight = torch.zeros(vocab_size, embedding_size))
        #生成function的映射向量
        self.embeddings_f = nn.Embedding(function_size, 2 * embedding_size, _weight = (torch.rand(function_size, 2 * embedding_size)-0.5)/embedding_size/2)
        #语境向量embedding
        self.embeddings_r = nn.Embedding(vocab_size, 2 * embedding_size, _weight = (torch.rand(vocab_size, 2 * embedding_size)-0.5)/embedding_size/2)

    def update(self, function_size_new, vocab_size_new):
        print("into update")
        device = self.embeddings.weight.device
        vocab_size, function_size, embedding_size = self.embeddings.num_embeddings, self.embeddings_f.num_embeddings, self.embeddings.embedding_dim
        if vocab_size_new != vocab_size:
            weight = torch.cat([self.embeddings.weight, torch.zeros(vocab_size_new - vocab_size, embedding_size).to(device)])
            self.embeddings = nn.Embedding(vocab_size_new, embedding_size, _weight=weight)
            weight_r = torch.cat([self.embeddings_r.weight, ((torch.rand(vocab_size_new - vocab_size, 2 * embedding_size)-0.5)/embedding_size/2).to(device)])
            self.embeddings_r = nn.Embedding(vocab_size_new, 2 * embedding_size, _weight=weight_r)
        self.embeddings_f = nn.Embedding(function_size_new, 2 * embedding_size, _weight=((torch.rand(function_size_new, 2 * embedding_size)-0.5)/embedding_size/2).to(device))

    def get_func_feature(self,func_vec):
        res = F.normalize(self.embeddings_f(func_vec), p=2, dim=1)
        return res


    def v(self, context_vec):

        #取段id
        len_vec=len(context_vec[0])

        v_f=context_vec[:,0:int(len_vec/3)]
        v_f = self.linear_f(v_f)

        v_prev=context_vec[:,int(len_vec/3):int(len_vec/3*2)]
        v_prev=self.linear_context(v_prev)
        v_next = context_vec[:, int(len_vec/3*2):int(len_vec)]
        v_next = self.linear_context(v_next)

        #剔除段id
        # e  = self.embeddings(inp[:,1:])
        #取前一条指令
        # v_prev = torch.cat([e[:,0], (e[:,1] + e[:,2]) / 2], dim=1)
        #取后一条指令向量
        # v_next = torch.cat([e[:,3], (e[:,4] + e[:,5]) / 2], dim=1)
        #生成语境向量+段向量
        v = ((v_f + v_prev + v_next) / 3)
        # print(v)
        # print(v.size())
        # exit()
        return v


    def forward(self, context_vec, center_vec):

        # device, batch_size = context_vec.device, context_vec.shape[0]

        #inp应该是语境向量+段向量，v是输入
        #torch.Size([1024, 200, 1])
        v = self.v(context_vec)


        pred=self.linear_output(v)

        label=center_vec

        # loss=bce(sigmoid(pred), label)
        loss = bce(softmax(pred), label)
        # print(loss)
        # exit()

        return loss

    def predict(self, context_vec, center_vec):
        device, batch_size = context_vec.device, context_vec.shape[0]
        v = self.v(context_vec)
        # probs = torch.bmm(self.embeddings_r(torch.arange(self.embeddings_r.num_embeddings).repeat(batch_size, 1).to(device)), v).squeeze(dim=2)
        pred = self.linear_output(v)
        pred=softmax(pred)
        return pred
