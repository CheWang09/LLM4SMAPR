from typing import Any
from openai import OpenAI
from transformers import T5ForConditionalGeneration, T5Tokenizer, AutoTokenizer, AutoModelForCausalLM

class LLM:
    # api_keys = {"openai":''}
    model_name = "gpt-3.5-turbo"
    
    def __init__(self, model_name, api_key = '') -> None:
        self.model_name = model_name
        match model_name:
            case 'gpt-3.5-turbo':
                if api_key != '':
                    self.api_keys = api_key
                self.initialize_gpt()
            case 'gpt-4':
                if api_key != '':
                    self.api_keys = api_key
                self.initialize_gpt()
            case 'CodeT5':
                self.initialize_codet5()
            case 'llama':
                self.initialize_llama()
            case _:
                print("Model is not supported by this tool!")

    def initialize_gpt(self):
        self.client = OpenAI(api_key=self.api_keys)

    def initialize_codet5(self):
        self.model = T5ForConditionalGeneration.from_pretrained('Salesforce/codet5-base')
        self.tokenizer = T5Tokenizer.from_pretrained('Salesforce/codet5-base')

    def initialize_llama(self):
        self.model = "meta-llama/LLaMA-13B"
        self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
        self.model = AutoModelForCausalLM.from_pretrained(self.model_name)        

    def LLMAnalyzeT5(self,prompt):
        input_ids = self.tokenizer.encode(prompt, return_tensors="pt")
        outputs = self.model.generate(input_ids, max_length=50, num_beams=4, early_stopping=True)
        fixed_code = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
        return fixed_code
    
    def LLMAnalyzeLlama(self,prompt):
        # 对输入文本进行编码
        input_ids = self.tokenizer.encode(prompt, return_tensors='pt')
        # 生成文本
        outputs = self.model.generate(input_ids, max_length=100, num_return_sequences=1)
        generated_text = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
        return generated_text

    def LLMAnalyzeGPT(self,prompt):
        completion = self.client.chat.completions.create(
            model= self.model_name,
            messages=[
            {"role": "user", "content": prompt},
            ]
        )
        return completion.choices[0].message.content
    
if __name__ == "__main__":
    print('test')
    test = LLM('gpt-3.5-turbo')
    test.initialize_gpt()
    





