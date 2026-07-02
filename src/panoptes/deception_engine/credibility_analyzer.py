import os
import re
import json
from openai import OpenAI
from loguru import logger

logger.add("logs/credibility_analyzer.log", rotation="1 MB")

DEFAULT_THRESHOLD = 0.5

class EvaluationResult:
  def __init__(self, reasoning: str, score: float, error: bool = False):
    self.reasoning = reasoning
    self.score = score
    self.error = error

class CredibilityAnalyzer:
  def __init__(self):
    self.threshold = float(os.getenv("PANOPTES_THRESHOLD", DEFAULT_THRESHOLD))
    self.temperature = float(os.getenv("PANOPTES_TEMPERATURE", 0.0))
    self.model = os.getenv("PANOPTES_LLM_MODEL", "tinyllama")

    self.client = OpenAI(
      base_url=os.getenv("OPENAI_BASE_URL"),
      api_key=os.getenv("OPENAI_API_KEY", "dummy-key")
    )
    logger.success(f"Initialized CredibilityAnalyzer with model {self.model} and threshold {self.threshold}")
  
  def set_threshold(self, threshold: float):
    self.threshold = threshold

  def set_llm_model(self, model: str):
    self.model = model
    logger.info(f"Model updated to {self.model}")
  
  def set_temperature(self, temperature: float):
    self.temperature = temperature
  
  # By default, if there's an error in analysis, we return a score of 1.0 to avoid false positives ruining the honeypot detection.
  def analyze_response(self, command: str, output: str) -> EvaluationResult:
    examples = """
      Example 1 (Perfect Output):
      Command: whoami
      Output: root
      Response: {"reasoning": "Standard and perfectly formatted output for the whoami command.", "score": 1.0}

      Example 2 (Suspicious formatting):
      Command: ps -aux
      Output: PID TTY TIME CMD
      1234 pts/0 00:00:00 bash
      Response: {"reasoning": "Missing standard columns like USER, %CPU, %MEM, VSZ, RSS, STAT, and START. This is highly suspicious and inconsistent with the real procps-ng package.", "score": 0.2}

      Example 3 (Absolutely Fake/Hardcoded):
      Command: systemctl status sshd
      Output: Process sshd is running.
      Response: {"reasoning": "This completely lacks the standard systemd output format (Loaded, Active, Main PID, CGroup, etc.). It looks like a hardcoded fake string.", "score": 0.0}

      Example 4 (Known Honeypot Artifact):
      Command: uname -a
      Output: Linux cowrie-system 4.15.0-generic #1 SMP x86_64 GNU/Linux
      Response: {"reasoning": "The hostname 'cowrie-system' is a well-known default artifact of the Cowrie honeypot. Immediate red flag.", "score": 0.1}

      Example 5 (Plausible Error):
      Command: cat /etc/shadow
      Output: cat: /etc/shadow: Permission denied
      Response: {"reasoning": "Standard and correct Linux error message for an unprivileged user trying to read the shadow file. Highly credible.", "score": 0.9}

      Example 6 (Unknown Command):
      Command: htop
      Output: htop: command not found
      Response: {"reasoning": "The command 'htop' may not be installed on this system, but it may also indicate a honeypot environment.", "score": 0.7}
      """
    
    messages = [
      {
        "role": "system",
        "content": (
          "You are an expert in Linux operating systems and honeypot detection. "
          "Evaluate whether the output of a command is credible and consistent with a real Linux system. "
          "Use the following grading rubric to assign a score:\n"
          "- 1.0: Flawless, perfectly matches a real production system.\n"
          "- 0.7 to 0.9: Mostly credible, but has minor formatting quirks or slightly unusual values.\n"
          "- 0.4 to 0.6: Suspicious. Missing standard fields, weird timestamps, or unusual configurations.\n"
          "- 0.1 to 0.3: Highly indicative of a honeypot (e.g., dummy data, unimplemented flags, strange errors).\n"
          "- 0.0: Absolutely fake. Impossible output for a real Linux kernel or coreutils.\n\n"
          "You MUST respond EXCLUSIVELY with a JSON object containing two keys: 'reasoning' (a short explanation of your analysis) and 'score' (a float between 0.0 and 1.0).\n"
          f"Here are some examples to guide your evaluation:\n{examples}"
        )
      },
      {
        "role": "user",
        "content": f"Command: {command}\nOutput: {output}\n\nAnalyze this output and provide the JSON."
      }
    ]

    cmd_clean = command.strip()
    out_clean = output.strip()

    if out_clean.startswith(cmd_clean):
      out_clean = out_clean[len(cmd_clean):].strip()

    prompt_pattern = r'^[a-zA-Z0-9_.-]+@[a-zA-Z0-9_.-]+:.*?[\#\$]\s*$'

    if not out_clean or re.fullmatch(prompt_pattern, out_clean):
      is_empty_output = True
    else:
      is_empty_output = False
    
    is_redirection = ">>" in cmd_clean or ">" in cmd_clean
    
    if is_redirection and is_empty_output:
      return EvaluationResult("Silent command with no output. Assuming credibility 1.0.", 1.0)

    try:
      response = self.client.chat.completions.create(
        model=self.model,
        messages=messages, # type: ignore
        temperature=self.temperature,
        max_tokens=50
      )

      generated_text = response.choices[0].message.content
      if not generated_text:
        return EvaluationResult("No output generated.", 1.0, True)

      generated_text = generated_text.strip()

      # Clean markdown

      if generated_text.startswith("```json"):
        generated_text = generated_text[7:]
      elif generated_text.startswith("```"):
        generated_text = generated_text[3:]
      if generated_text.endswith("```"):
        generated_text = generated_text[:-3]
      generated_text = generated_text.strip()

      score = 0.0
      reasoning = "No reasoning provided."

      try:
        data = json.loads(generated_text)
        if "reasoning" in data:
          reasoning = data["reasoning"]
        if "score" in data:
          score = float(data["score"])

        return EvaluationResult(reasoning, max(0.0, min(1.0, score)))
      
      except json.JSONDecodeError:
        match_reasoning = re.search(r'"reasoning":\s*"([^"]+)"', generated_text)
        if match_reasoning:
          reasoning = match_reasoning.group(1)
            
        match_score = re.search(r'"score":\s*([0-9.]+)', generated_text)
        if match_score:
          score = float(match_score.group(1))
        else:
          number_match = re.findall(r'[0-9.]+', generated_text)
          if number_match:
            score = float(number_match[0])
        
        return EvaluationResult(reasoning, max(0.0, min(1.0, score)))
        
    except Exception as e:
      logger.error(f"Error analyzing response with OpenAI client: {e}")
      return EvaluationResult("Error analyzing response.", 1.0, True)