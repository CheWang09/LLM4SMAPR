import re

class promptUtils:

    @staticmethod
    def query_relevant_elements(vul_desc,agent):
    #     prompt_template = """Role: You are an expert in solidity smart contract security and auditing.
    # Task: Your task is to analyze the vulnerability decription and output all contract name, function name, and state variable names exists in decription.
    # Expected Output: output shoule be strictly formatted as dicts, and the item is contract-function pair or contract-variable pair or function-variable pair like:{}
    # Below are required vulnerability informations:\n"""+vul_desc
        prompt_template = """Role: You are an expert in solidity smart contract security and auditing.
    Task: Your task is to analyze the vulnerability decription and output all contracts, functions exists in decription.
    Expected Output: output shoule be strictly formatted as list without any descriptions:
    [contract1,function1,function2,variable]
    Below are required vulnerability informations:\n"""+vul_desc
        response = agent.LLMAnalyzeGPT(prompt_template)
        return response
    
    @staticmethod
    def attack_analysis(vul_desc,CIG,agent):
        prompt_template = f"""Role: You are an expert in solidity smart contract security auditing.
        Task: You will be provided with an vulnerability description, functions' interactions of the real-world smart contract. Your task is to analyze the process by which the vulnerability occurred.
        Detailed Instructions:1. Review the provided analysis description carefully. 2. Identify and explain the sequence of events that led to the vulnerability.
        Expected Outcome: Output a sequence of procedures of how attacks can trigger this vulnerability.
        Below is the vulnerability informations:
        vulnerability description: {vul_desc};
        functions' interactions: {CIG}"""
        response = agent.LLMAnalyzeGPT(prompt_template)
        return response
    
    @staticmethod
    def generate_strategies(func_code, attacks, agent):
        prompt_template = f"""Role:You are an expert in solidity smart contract security auditing.
Task:You will be provided with the attack procedures, and core functions directly related to attacks of a real-world smart contract vulnerability. Your task is to provide methods to mitigate such vulnerabilities.
Expected Output: Just output specific code modification strategies(No more than three).
Below is the provided informations:
attack procedures: {attacks};
core function codes: {func_code}"""
        response = agent.LLMAnalyzeGPT(prompt_template)
        return response
    
    @staticmethod
    def code_supplement(func_code, attacks, agent):
        prompt_template = f"""Role:You are an expert in solidity smart contract security auditing.
Task:You will be provided with the attack procedures, and core functions directly related to attacks of a real-world smart contract vulnerability. Your task is to provide methods to mitigate such vulnerabilities.
Expected Output: Just output specific code modification strategies(No more than three).
Below is the provided informations:
attack procedures: {attacks};
core function codes: {func_code}"""
        response = agent.LLMAnalyzeGPT(prompt_template)
        return response
    
    @staticmethod
    def code_generate(func_code, attacks, strategies, agent):
        prompt_template = f"""Role:You are the expert in solidity smart contract security auditing.
        Task:You are provided with mitigation strategies, attack procedures, and relevant vulnerable code. Please fix the vulnerabilities with the minimum necessary modifications to ensure security and functionality.In additition, fix the code specifically and do not use any hypothetical functions.
        Expected Output: output vulnerable and patch function pairs. Strictly formatted as dicts without output any analysis.
        mitigation strategies: {strategies}; \n
        attack procedures: {attacks}; \n
        vulnerable function codes: {func_code}"""
        response = agent.LLMAnalyzeGPT(prompt_template)
        return response
    
    @staticmethod
    def code_validate(pair, vul_desc, agent):
        prompt_template = f"""Role:You are the expert in solidity smart contract security auditing.
        Task:You are provided with vulnerable-patch code snippet pairs and vulnerability descriptions. Please carefully analyze if patch code can fix the vulnerability.
        Expected Output: just output yes or no without any analysis.
        vulnerability descriptions: {vul_desc}; \n
        vulnerable-patch code snippet pairs: {pair}"""
        response = agent.LLMAnalyzeGPT(prompt_template)
        return response
    
    @staticmethod
    def patch_refine(pair, func_code, attacks, agent):
        prompt_template = f"""Role:You are the expert in solidity smart contract security auditing.
        Task:You are provided with error vulnerable-patch pairs, vulnerability attack procedures, and raw function codes. Please carefully refine patches to fix the vulnerability.
        Expected Output: fixed patch functions without any analysis.
        attack procedures: {attacks}; \n
        vulnerable-patch code snippet pairs: {pair}; \n
        raw function codes:{func_code}
        """
        response = agent.LLMAnalyzeGPT(prompt_template)
        return response
    
    
