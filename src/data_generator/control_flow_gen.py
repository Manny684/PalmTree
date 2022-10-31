from smda.Disassembler import Disassembler
from smda.common.SmdaReport import SmdaReport
import networkx as nx
import numpy as np
import matplotlib.pyplot as plt
from sklearn.feature_extraction.text import CountVectorizer
from itertools import product
from sklearn.decomposition import PCA
from  collections import Counter
import random
import os
import re
import pickle
import math

def parse_instruction(ins, symbol_map, string_map):
    ins = re.sub('\s+', ', ', ins, 1)
    parts = ins.split(', ')
    operand = []
    if len(parts) > 1:
        operand = parts[1:]
    for i in range(len(operand)):
        symbols = re.split('([0-9A-Za-z]+)', operand[i])
        for j in range(len(symbols)):
            if symbols[j][:2] == '0x' and len(symbols[j]) >= 6:
                if int(symbols[j], 16) in symbol_map:
                    symbols[j] = symbol_map[int(symbols[j], 16)]
                elif int(symbols[j], 16) in string_map:
                    symbols[j] = "string"
                else:
                    symbols[j] = "address"
        operand[i] = ' '.join(symbols)
    opcode = parts[0]
    return ' '.join([opcode]+operand)


def random_walk(g,length, symbol_map, string_map):
    sequence = []
    for n in g:
        if n != -1 and 'text' in g.nodes[n]:
            s = []
            l = 0
            s.append(parse_instruction(g.nodes[n]['text'], symbol_map, string_map))
            cur = n
            while l < length:
                nbs = list(g.successors(cur))
                if len(nbs):
                    cur = random.choice(nbs)
                    if 'text' in g.nodes[cur]:
                        s.append(parse_instruction(g.nodes[cur]['text'], symbol_map, string_map))
                        l += 1
                    else:
                        break
                else:
                    break
            sequence.append(s)
        if len(sequence) > 5000:
            print("early stop")
            return sequence[:5000]
    return sequence

def process_file(f, window_size):
    symbol_map = {}
    string_map = {}
    print(f)
    report = Disassembler().disassembleFile(f)
    symbol_map = get_symbols(report)
    #for string in bv.get_strings():
    #    string_map[string.start] = string.value

    function_graphs = {}

    for func in report.getFunctions():
        G = nx.DiGraph()
        label_dict = {}   
        add_map = {}
        for addr, insns in func.blocks.items():
            # print(block.disassembly_text)
            curr = addr
            predecessor = curr
            for inst in insns:
                disassembly = " ".join([inst.mnemonic, inst.operands])
                label_dict[addr] = disassembly
                G.add_node(curr, text=disassembly)
                if curr != addr:
                    G.add_edge(predecessor, curr)
                predecessor = curr
                curr += inst.getDetailed().size
            if addr in func.blockrefs:
                for edge in func.blockrefs[addr]:
                    G.add_edge(predecessor, edge)
        if len(G.nodes) > 2:
            function_graphs[func.offset] = G

    with open('cfg_train.txt', 'a') as w:
        for name, graph in function_graphs.items():
            sequence = random_walk(graph, 40, symbol_map, string_map)
            for s in sequence:
                if len(s) >= 4:
                    for idx in range(0, len(s)):
                        for i in range(1, window_size+1):
                            if idx - i > 0:
                                w.write(s[idx-i] +'\t' + s[idx]  + '\n')
                            if idx + i < len(s):
                                w.write(s[idx] +'\t' + s[idx+i]  + '\n')
    # gc.collect()


def get_symbols(report: SmdaReport):
    symbol_map = {}
    for f in report.getFunctions():
        for k, v in f.apirefs.items():
            symbol_map[k] = v.split("!")[1]
    return symbol_map


def main():
    bin_folder = '/path/to/binaries' 
    file_lst = []
    str_counter = Counter()
    window_size = 1;
    for parent, subdirs, files in os.walk(bin_folder):
        if files:
            for f in files:
                file_lst.append(os.path.join(parent,f))
    i=0
    for f in file_lst:
        print(i,'/', len(file_lst))
        process_file(f, window_size)
        i+=1

if __name__ == "__main__":
    main()