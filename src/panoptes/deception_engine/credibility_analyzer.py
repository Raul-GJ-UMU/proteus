import json
import re
import torch
from transformers import pipeline
from loguru import logger

logger.add("credibility_analyzer.log", rotation="1 MB")

DEFAULT_THRESHOLD = 0.5

class CredibilityAnalyzer:
  def __init__(self, model_id="TinyLlama/TinyLlama-1.1B-Chat-v1.0", threshold=DEFAULT_THRESHOLD):
    self.threshold = threshold

    self.pipeline = pipeline(
      "text-generation",
      model=model_id,
      dtype=torch.float16 if torch.cuda.is_available() else torch.float32,
      device_map="auto"
    )
    logger.success(f"Initialized CredibilityAnalyzer with model {model_id} and threshold {threshold}")
  
  def analyze_response(self, command: str, output: str) -> float:
    messages = [
      {
        "role": "system",
        "content": (
          "You are an expert in Linux operating systems and honeypot detection. "
          "Your task is to evaluate whether the output of a command is credible and consistent with a real Linux system. "
          "Respond EXCLUSIVELY with a JSON object containing the key 'score' (a number between 0.0 and 1.0)."
          "A score close to 1.0 indicates high credibility, while a score close to 0.0 indicates low credibility. "
          "Example: {\"score\": 0.95}"
        )
      },
      {
        "role": "user",
        "content": f"Command: {command}\nOutput: {output}\n\nEvaluate the credibility of this output and provide a score in the specified JSON format."
      }
    ]

    if not self.pipeline.tokenizer:
      logger.error("Tokenizer not found in the pipeline. Cannot analyze response.")
      return 0.0
    prompt = self.pipeline.tokenizer.apply_chat_template(messages, tokenize = False, add_generation_prompt = True)

    outputs = self.pipeline(
      prompt,
      max_new_tokens=30,
      do_sample=False,
      temperature=0.0
    )

    generated_text = outputs[0]['generated_text'].split("<|assistant|>")[-1].strip()
    logger.debug(f"Raw generated text: {generated_text}")

    try:
      match = re.search(r'"score":\s([0-9.]+)', generated_text)
      if match:
        score = float(match.group(1))
        return score
      else:
        # try to search for a number in the generated text if the JSON format is not strictly followed
        number_match = re.findall(r'[0-9.]+', generated_text)
        if number_match:
          score = float(number_match[0])
          return score
    except Exception as e:
      logger.error(f"Error parsing score from generated text: {e}")
      return 0.0
    
    return 0.0
