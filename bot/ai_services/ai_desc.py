import os
from openai import OpenAI
from bot.config import GIT_HUB_TOKEN

class CVESummarizer:
    def __init__(self):
        GIT_TOKEN = GIT_HUB_TOKEN
        self.client = OpenAI(
            base_url="https://models.inference.ai.azure.com",
            api_key=GIT_TOKEN,
            default_query={"api-version": "2024-08-01-preview"},
        )
        self.model = "gpt-4o"

    async def summarize(self, cve_description: str) -> str:
        try:
            response = self.client.chat.completions.create(
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a cybersecurity analyst. Your task is to analyze CVE bulletins based on their descriptions. "
                            "Summarize the vulnerability, explain it briefly, and provide specific suggested mitigations or actions. "
                            "Do not include extra commentary or introductions—only the core facts, explanation, and recommendations."
                        )
                    },
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "text",
                                "text": cve_description,
                            }
                        ],
                    },
                ],
                model=self.model,
                temperature=0.7,
                top_p=1,
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            return f"❌ Error during CVE summarization: {str(e)}"
