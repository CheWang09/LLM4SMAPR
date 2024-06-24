import subprocess
from slither.slither import Slither
import re
# ['0.5.0','0.6.12','0.6.8','0.7.6','0.8.0','0.8.1','0.8.3','0.8.4','0.8.7']

class compliationUtils:
    # 下载地址模板
    url_template = "https://github.com/ethereum/solidity/releases/download/v{version}/solc-static-linux"

    ## 下载指定版本的solc versions
    @staticmethod
    def download_solc(version):
        url = cls.url_template.format(version=version)
        output_file = f"solc-v{version}"
        
        try:
            # 下载指定版本的 solc
            print(f"Downloading solc version {version} from {url}...")
            subprocess.run(['wget', '-O', output_file, url], check=True)
            
            # 设置执行权限
            print(f"Setting executable permissions for {output_file}...")
            subprocess.run(['chmod', '+x', output_file], check=True)
            
            print(f"Downloaded and set permissions for solc version {version}.\n")
            
        except subprocess.CalledProcessError as e:
            print(f"An error occurred while downloading solc version {version}: {e}")

    
    @staticmethod
    def extract_solidity_version(content):
        # 更新的正则表达式匹配 pragma solidity 后面的版本号，考虑 ^ 和 >= 等运算符
        pattern = r'pragma solidity\s*(\^|>=)?\s*(\d+\.\d+\.\d+);'
        match = re.search(pattern, str(content))
        if match:
            return match.group(2)  # 返回版本号部分
        else:
            return None

    @staticmethod
    def compile(file_path,solc_remaps):
        try:
            slither = Slither(file_path, solc_remaps=solc_remaps)
        except Exception as e:
            return e
        return True
    
    @staticmethod
    def compilation_check(file_path,solc_remaps=''):
        check = cls.compile(file_path,solc_remaps)
        if re.findall("SlitherError",str(type(check))):
            error = str(check)
            if re.findall("requires different compiler version",error):
                version = cls.extract_solidity_version(error)
                print("Solc Version Error that need: ",version)
                print("Switching to ",version)
                result = subprocess.run(['solc-select', 'use', version], capture_output=True, text=True)
                if result.returncode == 1:
                    print(f"Solc Verison {version} Not Existing, please download it.")
            elif re.findall(r'Error: Source "([^"]+)" not found: File not found\.',str(result)):
                lack_files = re.findall(r'Error: Source "([^"]+)" not found: File not found\.',str(result))
                lack_files = list(set([x.split("/")[0] for x in lack_files]))
                print("File not found: ","\t".join(lack_files))
            else:
                print(error)
            return
        print("Successful Compilation!")
        return 
    
if __name__ == "__main__":
    file_path = ''
    solc_remaps = []
    compliationUtils.compilation_fix(file_path,solc_remaps)

    ## download solc verison
    compliationUtils.download_solc("0.8.0")