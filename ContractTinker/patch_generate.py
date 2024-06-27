import re
import os
import logging
import time
from program_analysis import StaticUtils
from LLM_Interfaces import LLM
from DocumentParsing import documentParsing
from promptsUtils import promptUtils
import argparse

class CustomLogger(logging.Logger):
    def __init__(self, name, level=logging.NOTSET):
        super().__init__(name, level)
        self.propagate = False

        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.addHandler(handler)
        handler = logging.FileHandler(name)
        self.addHandler(handler)

def arguments():
    parser = argparse.ArgumentParser(description='Requir report path; project path, solc_remaps')
    
    parser.add_argument('--report_path', type=str, required=True, help='report path')
    parser.add_argument('--project_path', type=str, required=True, help='project path')
    parser.add_argument('--solc_remaps', type=str, required=False, help='solc remapping for compile')
    parser.add_argument('--vul_name', type=str, required=False, help='vulnerability name')
    parser.add_argument('--output', type=str, required=False, help='output path')

    args = parser.parse_args()
    return args

def elements_matching(elements_lists,contracts):
    ## contract name matching
    all_contracts_names = contracts.keys()
    contract_elements = []
    for ele in elements_lists:
        if ele in all_contracts_names:
            contract_elements.append(ele)
    
    ## 获取核心合约函数
    core_contract_functions = {}
    other_contract_functions = {}
    # if contract_elements:
    #     for contract in contract_elements:
    #         core_contract_functions[contract] = []
    #         contract_slither = contracts[contract]['content']
    #         for func in contract_slither.functions:
    #             core_contract_functions[contract].append(func.name)
    if contract_elements:
        for contract in contract_elements:
            contract_slither = contracts[contract]['content']
            for func in contract_slither.functions:
                if func.name not in core_contract_functions:
                    core_contract_functions[func.name] = []
                core_contract_functions[func.name].append(contract)

    ## 获取边缘合约函数
    for contract in all_contracts_names:
        if contract not in contract_elements:
            contract_slither = contracts[contract]['content']
            for func in contract_slither.functions:
                if func.name not in other_contract_functions:
                    other_contract_functions[func.name] = []
                other_contract_functions[func.name].append(contract)

    ## function matching
    function_elements = {}
    for ele in elements_lists:
        if ele not in contract_elements:
            if ele in core_contract_functions:
                function_elements[ele] = core_contract_functions[ele] # list 
            elif ele in other_contract_functions:
                function_elements[ele] = other_contract_functions[ele] # list
    
    return function_elements,contract_elements,core_contract_functions,other_contract_functions

def relevant_functions(function_elements,interaction_graph,core_contract_functions,other_contract_functions):
    relevant_functions = []

    function_pairs = []
    for func in function_elements.keys():
        rel = interaction_graph.get(func,[])
        relevant_functions.extend(rel)
        for rf in rel:
            if not re.match("require(.*)",rf):
                function_pairs.append(func+"@"+rf)
    function_pairs = list(set(function_pairs))
    function_pairs = [x.split("@") for x in function_pairs]

    ## 
    relevant_functions = list(set(relevant_functions))
    relevant_function_elements = {}
    for func in relevant_functions:  
        if func in core_contract_functions:
            relevant_function_elements[func] = core_contract_functions[func] # list 
        elif func in other_contract_functions:
            relevant_function_elements[func] = other_contract_functions[func] # list
    return relevant_function_elements,function_pairs

# {'function name':'contract name','variable name':'contract name'}
def extract_target_functions(vul_loc):
    pass

def get_func_body(contract,name):
    for func in contract.functions:
        if func.name == name:
            return func.source_mapping.content
    return 0

def gather_code_snippets(function_elements,contract_elements,relevant_function_elements,contracts):

    ## 目前只针对 当前核心函数的合约的关联函数
    # contracts_slither = {}
    contracts_codes = {}
    for contract in contract_elements:
        # contracts_slither[contract] = contracts[contract]['content']
        contracts_codes[contract] = {}
        tmp_slither = contracts[contract]['content']

        for ele,cot in function_elements.items():
            if contract in cot:
                body = get_func_body(tmp_slither,ele)
                contracts_codes[contract][ele] = body
        
        for ele,cot in relevant_function_elements.items():
            if contract in cot:
                body = get_func_body(tmp_slither,ele)
                contracts_codes[contract][ele] = body

    return contracts_codes    

def contextual_prepare(structural_infos,interaction_graph,contracts,agent):
    # print("Program slicing...")
    ## First extracting relevant elements based on documents info
    vul_loc = structural_infos['Vulnerability location']
    vul_desc = structural_infos['Vulnerability description']
    vul_loc = {}
    if len(vul_loc) != 0:
        print("Extracting relevant elements based on regex funcs...")
        target_functions = extract_target_functions(vul_loc)
        target_rel_eles = []
        for func in target_functions:
            RAG_function = contracts.get(func,[])
            target_rel_eles.extend(RAG_function)
    
    ## query relevant functions by llm

    # testing
    response = promptUtils.query_relevant_elements(vul_desc,agent)
    elements_lists = response.strip('[]').split(', ')
    # elements_lists = ['MarginRouter', 'crossSwapExactTokensForTokens', '_swapExactT4T', '_swap', 'amounts', 'pairs', 'tokens', 'registerTrade', 'startingBalance', 'pair', 'FUND', 'ATTACKER_CONTRACT', 'WETH', 'WBTC', 'WETH_WBTC_PAIR']
    function_elements,contract_elements,core_contract_functions,other_contract_functions = elements_matching(elements_lists,contracts)

    relevant_function_elements,function_pairs = relevant_functions(function_elements,interaction_graph,core_contract_functions,other_contract_functions)

    code_snippets = gather_code_snippets(function_elements,contract_elements,relevant_function_elements,contracts)

    return function_elements,relevant_function_elements,code_snippets,function_pairs

class Repair:
    def __init__(self,report_path,project_path,solc_remaps='',model_name='gpt-3.5-turbo') -> None:
        self.report_path = report_path
        self.project_path = project_path
        self.solc_remaps = solc_remaps
        self.model_name = model_name

        logging.setLoggerClass(CustomLogger)
        self.logger = logging.getLogger(report_path)
        self.logger.setLevel(logging.DEBUG)
 
        self.logger.info("Reading documents...")
        self.report = documentParsing(report_path)
        self.report.parse_raw_file()
        self.structural_informations = self.report.extract_structural_information()

        self.logger.info("Reading program...")
        self.project_info = StaticUtils(self.project_path,self.solc_remaps)
        ### reading all sol files
        self.project_info.extract_all_files()
        ### reading all contracts
        self.project_info.contruct_raw_contract_database()
        ## call graph generate
        self.project_info.call_graph_generation()
        ## extract and parse all dot files
        self.project_info.extract_all_dot_files()
        ## generate interaction graphs
        self.project_info.generate_interaction_graph()

        self.logger.info("Initialize LLM...")
        self.generator = LLM(model_name)
        self.validator = LLM("gpt-4")

    def chainOfprompts(self,structural_infos,context):
        vul_desc = structural_infos['Vulnerability description']
        function_interactions = "\n".join([" -> ".join(pair) for pair in context[-1]])

        self.contract_codes = []
        for k,v in context[-2].items():
            codes = "\n".join(v.values())
            codes = k+"\n"+codes+"\n"
            self.contract_codes.append(codes)

        self.logger.info("Attack Procedure analyzing...")
        attack_procedures = promptUtils.attack_analysis(vul_desc,function_interactions,self.generator)
        # self.logger.info(attack_procedures)

        self.logger.info("Strategies analyzing")
        strategies = promptUtils.generate_strategies("\n".join(self.contract_codes),attack_procedures,self.generator)
        # self.logger.info(strategies)

        self.logger.info("Code supply...")
        # supple_codes = promptUtils.code_supplement("\n".join(contract_codes),attack_procedures,self.generator)

        self.logger.info("Patch generating...")
        codes_pairs = promptUtils.code_generate("\n".join(self.contract_codes),attack_procedures,strategies,self.generator)

        # self.logger.info(codes_pairs)
        return codes_pairs

    def validate(self,structural_infos):
        vul_desc = structural_infos['Vulnerability description']
        eval = promptUtils.code_validate(self.patch_pairs,vul_desc,self.validator)

        if eval == 'No':
            refine_patches = promptUtils.patch_refine(self.patch_pairs, "\n".join(self.contract_codes),vul_desc,self.generator)
            return refine_patches 
        
        return self.patch_pairs
        
    def contractFixer(self,risk_name = 'Re-entrancy bug allows inflating balance'):
        ##
        # structural_infos = {
        # "Vulnerability description":'',
        # "Vulnerability location": {},
        # "Recommendation description":''
        # } 

        ## 以一个漏洞为例进行分析
        structural_infos = self.structural_informations[risk_name]
        interaction_graph = self.project_info.edge_relations
        contracts = self.project_info.contracts
        
        #context = function_elements,relevant_function_elements,code_snippets,function_pairs
        self.context = contextual_prepare(structural_infos,interaction_graph,contracts,self.generator)
        self.patch_pairs = self.chainOfprompts(structural_infos,self.context)

        final_patches = self.validate(structural_infos)

        self.logger.info("Successfully!")
        return final_patches

if __name__ == "__main__":

    args = arguments()
    report_path = args.report_path
    project_path = args.project_path
    vul_name = args.vul_name
    solc_remaps = args.solc_remaps
    output_path = args.output

    if solc_remaps:
        solc_remaps = solc_remaps.split(" ")
        repair = Repair(report_path,project_path,solc_remaps)
    else:
        repair = Repair(report_path,project_path)
    
    result = repair.contractFixer(vul_name)

    # repair.logger.info("Report path :",report_path)
    # repair.logger.info("Project path :",project_path)
    # repair.logger.info("Vulnerability name :",vul_name)

    repair.logger.info(result)

    if output_path:
        with open(output_path,'w') as f:
            f.write(result)
    else:
        formatted_time = time.strftime("%Y%m%d-%H%M%S", time.localtime(time.time()))
        with open(f"result_{formatted_time}.txt",'w') as f:
            f.write(result)