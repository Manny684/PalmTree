import networkx as nx
import random
import re
import json
from idautils import *
from idaapi import *
from idc import *
from pathlib import Path

def parse_instruction(ins, symbol_map, string_map):
    with open(Path(__file__).parent / "insns.txt", "a") as f:
        f.write(ins + "\n")
    ins = re.sub('\s+', ', ', ins, 1)
    parts = ins.split(', ')
    operand = []
    if len(parts) > 1:
        operand = parts[1:]
    for i in range(len(operand)):
        symbols = re.split('([0-9A-Za-z_]+)', operand[i])
        for j in range(len(symbols)):
            pass
            # if symbols[j][:2] == '0x' and len(symbols[j]) >= 6:
            #     if int(symbols[j], 16) in symbol_map:
            #         symbols[j] = "symbol"
            #     elif int(symbols[j], 16) in string_map:
            #         symbols[j] = "string"
            #     else:
            #         symbols[j] = "address"
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

def process_file(window_size):
    with open(DEBUG, "w") as debugfile:
        debugfile.write("Start\n")
        symbol_map = get_symbol_map()
        json.dump(symbol_map, debugfile, indent=4)
        string_map = {}
        for string in Strings():
            string_map[string.ea] = str(string)

        function_graphs = {}

        for func_ea in Functions():
            G = nx.DiGraph()
            function = get_func(func_ea)
            flowchart = FlowChart(function)
            for block in flowchart:
                predecessor = block.start_ea
                for inst in Heads(block.start_ea, block.end_ea):
                    G.add_node(inst, text=GetDisasm(inst))
                    if inst != block.start_ea:
                        G.add_edge(predecessor, inst)
                    predecessor = inst
                for successor_block in block.succs():
                    G.add_edge(predecessor, successor_block.start_ea)
            if len(G.nodes) > 2:
                function_graphs[func_ea] = G

        with open(Path(__file__).parent / 'cfg_train.txt', 'a') as w:
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
        # TODO
        # 1. Instructions are doubled, but why x-x
        # 2. Calls and Strings must be identified
        # for ea, graph in function_graphs.items():
        #     nx.readwrite.write_edgelist(graph, Path(file).parent / str(ea))


def get_symbol_map():
    module_count = get_import_module_qty()
    symbol_map = dict()
    def import_callback(ea, name, _):
        if "@" in name:
            symbol_map[ea] = name.split("@")[0]
        else:
            symbol_map[ea] = name
        return True

    for i in range(module_count):
        enum_import_names(i, import_callback)
    return symbol_map


DEBUG = "/home/he1n/phd/PalmTree/src/data_generator/debug.txt"
def main():
    """
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
    """
    auto_wait()
    process_file(1)
    qexit(0)

main()
