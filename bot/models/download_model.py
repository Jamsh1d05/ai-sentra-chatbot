from transformers import BartForConditionalGeneration, BartTokenizer

model_name = "sshleifer/distilbart-cnn-12-6"

print("Downloading model and tokenizer...")
model = BartForConditionalGeneration.from_pretrained(model_name)
tokenizer = BartTokenizer.from_pretrained(model_name)

print("Model and tokenizer downloaded successfully.")

