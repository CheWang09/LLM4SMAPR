import re
import json


class documentParsing:
    project_path = ''
    contract_name = ''
    report_path = ''
    parsed_report_path = ''

    def __init__(self, report_path,parsed_report_path='') -> None:
        self.report_path = report_path
        self.parsed_report_path = parsed_report_path

    def extract_vul_locations(self,text):
        # 定义多个正则表达式模式
        patterns = [
            r'(\b\w+\.sol\b)\#\[L(\d+)\]',  # 匹配 .sol#[L行号]
            r'(\b\w+\.sol\b)\[L(\d+)\]',    # 匹配 .sol[L行号]
            r'(\b\w+\.sol\b)\#L(\d+)',      # 匹配 .sol#L行号
            r'(\b\w+\.sol\b)\sL(\d+)',      # 匹配 .sol L行号
            # r'(\b\w+\.sol\b)',              # 匹配没有行号的 .sol
            r'(\b\w+\.sol\b)(?:[\[#L](\d+)\])?'
        ]
        matches = []
        # 查找所有匹配项
        for pattern in patterns:
            matches.extend(re.findall(pattern, text))
        # 过滤并格式化结果
        results = []
        for match in matches:
            if len(match) == 2:
                filename, line_number = match
                results.append((filename, line_number))
            else:
                filename = match[0]
                results.append((filename, 'None'))
        # 去除重复项
        results = list(set(results))
        output = {}
        # 输出结果
        for filename, line_number in results:
            if filename not in output:
                output[filename] = []
            output[filename].append(line_number)
        return output
        
    def extract_description(self,document):
        # 删除注释部分的正则表达式
        comment_pattern = re.compile(r'\*\*.*?\*\*:\s*>.*?(?=(\*\*|$))', re.DOTALL)
        # 正则表达式
        vuln_pattern = re.compile(r"(.*?)(\n)?Recommend", re.DOTALL)
        recommendation_pattern = re.compile(r"Recommend(.*)", re.DOTALL)

        # clean github links
        clean_pattern = re.compile(r'\*\*\[.*?\]\(https://github.com/.*?\):\*\*.*')
        clean_gitub_pattern = re.compile(r'\(https://github\.com/[a-zA-Z0-9-]+/[a-zA-Z0-9-]+/blob/[a-f0-9]+/.+?\)')
        # clean comments
        cleaned_document = re.sub(comment_pattern, '', document)

        # 提取漏洞分析部分
        vuln_match = vuln_pattern.search(cleaned_document)
        vuln_description_raw = vuln_match.group(1).strip() if vuln_match else "N/A"
        
        ## if vuln_description_raw is "N/A", then all description is vuln_description
        if vuln_description_raw == "N/A":
            vuln_description_raw = cleaned_document

        ## 清理github 链接
        vuln_description = re.sub(clean_gitub_pattern, '', vuln_description_raw)

        ## 清理无用文本
        vuln_description_lines = [x for x in vuln_description.split("\n") if not re.match("^_Submitted by.*",x)]
        vuln_description = "\n".join(vuln_description_lines)

        # 提取修复建议部分
        recommendation_match = recommendation_pattern.search(cleaned_document)
        recommendation_description = "Recommend " + recommendation_match.group(1).strip() if recommendation_match else "N/A"

        recommendation_description_lines = [x for x in recommendation_description.split("\n") if x != '']
        recommendation_description = []
        for line in recommendation_description_lines:
            if clean_pattern.match(line):
                break
            else:
                recommendation_description.append(line)

        recommendation_description = "\n".join(recommendation_description)
        recommendation_description = re.sub(clean_gitub_pattern, '', recommendation_description)

        ## extract vulnerability locations
        vul_locations = self.extract_vul_locations(vuln_description_raw)

        # 输出结果
        output = {
            "Vulnerability description": vuln_description,
            "Vulnerability location":vul_locations,
            "Recommendation description": recommendation_description
        }

        return output

    ## 读取 所有找到带有recommendation的high risk漏洞， 并抽取对应的部分
    def extract_structural_information(self):
        contract_structural_information = {}
        with open(self.parsed_report_path,'r') as f:
            content = f.read()
        # 漏洞dicts
        vuls = json.loads(content)['HighRiskFindings']
        contract_risk_list = vuls.keys()

        for risk_name in contract_risk_list:
            risk_content = vuls[risk_name]
            ## extract vulnerabilit description, location, and recommendations.
            output = self.extract_description("\n".join(risk_content))
            contract_structural_information[risk_name]=output
        return contract_structural_information
    
    def parse_raw_file(self,output_file='./'):
        try:
            with open(self.report_path,'r') as f:
                md = f.read()
        except:
            print(f"Open {self.report_path} file error! Plz check file path!")
            raise 
        
        ## 拆分文档
        md = [x for x in md.split("\n") if x != '']
        ## 找到high risk findings , medium risk findings, low risk findings的位置
        HighRiskFindings = 0
        MediumRiskFindings = 0
        LowRiskFindings = 0
        for i,content in enumerate(md):
            # if len(content) <=30:
            #     print(content)
            if re.match("#? High Risk Findings",content) and HighRiskFindings == 0:
                HighRiskFindings = i
            if re.match("#? Medium Risk Findings",content) and MediumRiskFindings == 0:
                MediumRiskFindings = i
            if re.match("#? Low Risk Findings|#? Low Risk and Non-Critical Issues",content) and LowRiskFindings == 0:
                LowRiskFindings = i

        if MediumRiskFindings == 0 and LowRiskFindings != 0:
            MediumRiskFindings = LowRiskFindings

        try:
            assert HighRiskFindings<MediumRiskFindings<=LowRiskFindings
        except:
            print(f"finding vulnerability error!")
            raise 
        
        HighRiskFindingsPart = md[HighRiskFindings+1:MediumRiskFindings]
        MediumRiskFindingsPart = md[MediumRiskFindings+1:LowRiskFindings]

        ## for each part
        contentOfFindings = {'HighRiskFindings':HighRiskFindingsPart,'MediumRiskFindings':MediumRiskFindingsPart}
        vulnerability = {'HighRiskFindings':{},'MediumRiskFindings':{}}
        try:
            for key,value in contentOfFindings.items():
                vul_name = None
                for content in value:
                    if re.match("(##)? \[\[",content):
                        vul_name = re.findall('(?<=\]).*(?=\]\()',content)[0].strip()
                        vulnerability[key][vul_name] = []
                    else:
                        if vul_name is not None:
                            vulnerability[key][vul_name].append(content)
        except:
            print(self.report_path," Error in storing data.")
        
        self.parsed_report_path = f"{output_file}/vulnerability.json"
        with open(self.parsed_report_path,'w') as f:
            json.dump(vulnerability,f,indent=4)
    
if __name__ == "__main__":
    print('test')
    test = documentParsing("/home/LLM4APR/dataset/3/3.md")
    test.parse_raw_file()

    structural_information = test.extract_structural_information()
    # print(structural_information)
