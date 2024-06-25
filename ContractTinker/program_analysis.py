import os
import re
import subprocess
import networkx as nx
from slither.slither import Slither
from tqdm import tqdm

class StaticUtils:
    project_path = ''
    contract_name = ''
    all_sol_files = ''
    solc_remaps = ''
    contracts = ''
    all_dot_files = ''
    edge_relations = ''

    ## 1
    def __init__(self,project_path,solc_remaps='') -> None:
        self.project_path = project_path
        self.solc_remaps = solc_remaps

    ### search entire files to find out these functions 先找到所有的文件
    def findout_allsol(self,path,tmp_sol_files=[]):
        tmp_files = os.listdir(path)
        for fl in tmp_files:
            if re.match(".*sol$",fl) and os.path.isfile(path+fl):
                tmp_sol_files.append(path+fl)
            elif os.path.isdir(path+fl):
                if fl == 'node_modules':
                    continue
                self.findout_allsol(path+f"{fl}/",tmp_sol_files)
        return tmp_sol_files
    
    ## 2
    def extract_all_files(self):
        print("Reading all .sol files...")
        self.all_sol_files = self.findout_allsol(self.project_path)
        
    ## extract all functions and its body name
    def construct_raw_function_database(self):
        code_dicts = {}
        funcname_pattern = re.compile(r'function\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(')

        ## extract features of each functions
        funcscope_pattern = re.compile(r'external|internal|public|private|pure|view|payable')

        for sol in self.all_sol_files:
            with open(sol,'r') as f:
                code = f.read()
            # Regular expression to extract functions including their modifiers and bodies
            functions = re.findall(r'\bfunction\s+[\w]+\s*\(.*?\)\s*(?:\w+\s+)*{.*?}', code, re.DOTALL)

            # func_codes = {}
            for func in functions:
                func_name = funcname_pattern.findall(func)[0]
                func_scopes = funcscope_pattern.findall(func)
                code_dicts[func_name] = {'function_code':func,'func_scope':func_scopes,'sol_file':sol}
        
        self.code_dicts = code_dicts
        return code_dicts
    
    ## 2
    ## adopt slither to contract raw contracts database
    def contruct_raw_contract_database(self,solc_remap=''):
        print("contruct raw contract database...")
        if solc_remap != '':
            self.solc_remaps = solc_remap
        contracts2mapping = {}
        for sol in tqdm(self.all_sol_files):
            # print(self.solc_remaps)
            slither = Slither(sol,solc_remaps=self.solc_remaps)

            for contract in slither.contracts:
                if contract.name not in contracts2mapping:
                    # print(f'Contract: {contract.name}')
                    contracts2mapping[contract.name] = {'FromFile':sol,'content':contract}
        print("Total Contracts are:",len(contracts2mapping))

        self.contracts = contracts2mapping
        return 
    
    def call_graph_generation(self):
        print("Generating call graphs")
        solc_remap_str = ' '.join(self.solc_remaps)
        for sol in tqdm(self.all_sol_files):
            command = f'slither {sol} --solc-remaps \"{solc_remap_str}\" --print call-graph'
            try:
                # todo logging
                result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
            except Exception as e:
                print(e)
        return 
            
    def get_all_dot_files(self,path,all_dot_files=[]):
        tmp_files = os.listdir(path)
        for fl in tmp_files:
            if re.match(".*dot$",fl) and os.path.isfile(path+fl):
                all_dot_files.append(path+fl)
            elif os.path.isdir(path+fl):
                self.get_all_dot_files(path+f"{fl}/",all_dot_files)
        return all_dot_files

    def extract_all_dot_files(self):
        print("Reading all dot files")
        self.all_dot_files = self.get_all_dot_files(self.project_path)
    
    def subt(self,a):
        return re.sub(r'\b\d+_', '', a)

    def generate_interaction_graph(self):
        edge_relations = {}
        for dot_file in self.all_dot_files:
            G = nx.drawing.nx_agraph.read_dot(dot_file)
            for a,b in list(G.edges()):
                clean_a = self.subt(a)
                clean_b = self.subt(b)

                if clean_a not in edge_relations:
                    edge_relations[clean_a] = []
                edge_relations[clean_a].append(clean_b)

        for k,v in edge_relations.items():
            edge_relations[k] = list(set(v))

        self.edge_relations = edge_relations
        return edge_relations
        
if __name__ == "__main__":
    print('test')

    solc_remaps = ["@openzeppelin=/home/LLM4APR/dataset/3/contracts_3/contracts/node_modules/@openzeppelin",
               "@uniswap=/home/LLM4APR/dataset/3/contracts_3/contracts/node_modules/@uniswap",
               "hardhat=/home/LLM4APR/dataset/3/contracts_3/contracts/node_modules/hardhat",
               "interfaces=/home/LLM4APR/dataset/3/contracts_3/interfaces"]
    
    test = StaticUtils("/home/LLM4APR/dataset/3/contracts_3/",solc_remaps)

    test.extract_all_files()
    # test.contruct_raw_contract_database()
    
    ## call graph generate
    test.call_graph_generation()
    
    ## extract and parse all dot files
    test.extract_all_dot_files()

    test.generate_interaction_graph()
