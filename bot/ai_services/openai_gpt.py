from openai import OpenAI
from bot.config import GIT_HUB_TOKEN

token = GIT_HUB_TOKEN

class GitHubGPT:
    def __init__(self, token: str):
        self.client = OpenAI(
            base_url="https://models.github.ai/inference",
            api_key=token,
        )
        self.model = "openai/gpt-4.1-mini"

    async def ask(self, prompt: str) -> str:
        try:
            response = self.client.chat.completions.create(
                messages=[
                    {"role": "system", "content": "You are a helpful cybersecurity assistant virtual assistant and your task is to answerany question related to cybersecurity, vulnerabilities, exploits, and related topics. You are also able to provide information about CVEs with direct official link of the vendor and other security-related queries.Just give the clear answer to the question, and do not ask any other questions from user"},
                    {"role": "user", "content": prompt}
                ],
                temperature=1.0,
                top_p=1.0,
                model=self.model
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            return f"❌ Error: {str(e)}"
