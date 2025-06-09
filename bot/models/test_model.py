from transformers import pipeline

summarizer = pipeline("summarization", model="sshleifer/distilbart-cnn-12-6")

cve_text = """
A vulnerability has been identified in SIMATIC PCS neo V4.1 (All versions), SIMATIC PCS neo V5.0 (All versions), SINEC NMS (All versions), SINEMA Remote Connect (All versions), Totally Integrated Automation Portal (TIA Portal) V17 (All versions), Totally Integrated Automation Portal (TIA Portal) V18 (All versions), Totally Integrated Automation Portal (TIA Portal) V19 (All versions), Totally Integrated Automation Portal (TIA Portal) V20 (All versions), User Management Component (UMC) (All versions < V2.15.1.1). Affected products contain a out of bound read buffer overflow vulnerability in the integrated UMC component. This could allow an unauthenticated remote attacker to cause a denial of service condition.
"""

summary = summarizer(cve_text, max_length=len(cve_text.split()), min_length=10, do_sample=False)
print("🧠 Summary:", summary[0]['summary_text'])


