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
    self.verdict = ""
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
  
  def set_temperature(self, temperature: float):
    self.temperature = temperature
  
  # By default, if there's an error in analysis, we return a score of 1.0 to avoid false positives ruining the honeypot detection.
  def analyze_response(self, command: str, output: str, oracle_output: str) -> EvaluationResult:
    
    vbox_artifacts_pattern = r'(VirtualBox|innotek GmbH|Oracle Corporation|HVM|KVM|vboxguest|vboxsf|vboxvideo|vmware|\bVBoxService\b|\bVBoxClient\b|08:00:27)'
    oracle_sanitized = re.sub(vbox_artifacts_pattern, ' ', oracle_output, flags=re.IGNORECASE).strip()

    cmd_clean = command.strip()
    out_clean = output.strip()

    if out_clean.startswith(cmd_clean):
      out_clean = out_clean[len(cmd_clean):].strip()

    prompt_pattern = r'[\r\n]*[a-zA-Z0-9_.-]+@[a-zA-Z0-9_.-]+:.*?[\#\$]\s*$'
    out_clean = re.sub(prompt_pattern, '', out_clean).strip()

    is_empty_output = (len(out_clean) == 0)

    logger.debug(f"Oracle Output: {oracle_sanitized}\nActual Output: {out_clean}")

    if oracle_sanitized == out_clean:
      return EvaluationResult("Output matches the oracle output. Assuming credibility 1.0.", 1.0)
    
    is_redirection = ">>" in cmd_clean or ">" in cmd_clean
    
    if is_redirection and is_empty_output:
      return EvaluationResult("Silent command with no output. Assuming credibility 1.0.", 1.0)

    examples = """
      Example 1 (Dynamic Data Match):
      Command: w
      Oracle: 15:37 up 29 min, 1 user...
      Output: 16:20 up 2 days, 1 user...
      Response: {"reasoning": "Structurally perfectly matches the Oracle. Differences in timestamps, users, and IPs are expected dynamic data.", "verdict": "Credible", "score": 1.0}

      Example 2 (Structural Failure):
      Command: w
      Oracle: 15:37 up 29 min, 1 user...
      Output: User root is logged in.
      Response: {"reasoning": "The output completely lacks the standard column structure (USER, TTY, FROM...) seen in the Oracle.", "verdict": "Fake", "score": 0.0}

      Example 7 (Almost equal but with minor differences):
      Command: kldstat
      Oracle: bash: line 1: kldstat: command not found
      Output: bash: kldstat: command not found
      Response: {"reasoning": "The output is structurally similar to the Oracle, but the Oracle includes 'line 1:' which is missing in the honeypot output. Minor structural difference.", "verdict": "Mostly Credible", "score": 0.85}
      
      Example 3 (Minor formatting quirks):
      Command: ps -aux
      Oracle: USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND ...
      Output: USER PID TTY TIME CMD ...
      Response: {"reasoning": "Output looks like a valid process list but is missing some keywords or columns present in the Oracle like %CPU and %MEM.", "verdict": "Suspicious", "score": 0.6}

      Example 4 (Suspicious/Malformed):
      Command: cat /etc/passwd
      Oracle: root:x:0:0:root:/root:/bin/bash ...
      Output: User root, User www-data ...
      Response: {"reasoning": "The output may be ignoring the standard structure expected, but shows some similarity.", "verdict": "Suspicious", "score": 0.4}

      Example 5 (Bad formatting):
      Command: ps -aux
      Output: PID TTY TIME CMD
      1234 pts/0 00:00:00 bash
      Response: {"reasoning": "Missing standard columns like USER, %CPU, %MEM, VSZ, RSS, STAT, and START. This is highly suspicious and inconsistent with the real procps-ng package.", "verdict": "Probably Fake", "score": 0.2}

      Example 6 (Missing Tool / Error when Oracle succeeds):
      Command: ifconfig
      Oracle: enp0s3: flags=4163<UP,BROADCAST,RUNNING,MULTICAST> mtu 1500...
      Output: ifconfig is missing from the machine. skipping...
      Response: {"reasoning": "The Oracle successfully returned network interfaces, but the honeypot failed to execute the command or returned an error string. Severe structural mismatch.", "verdict": "Fake", "score": 0.1}
      """
    
    if oracle_output and oracle_output not in ["ORACLE_UNAVAILABLE", "ORACLE_TIMEOUT_OR_ERROR"]:
      system_content = (
        "You are an expert in Linux operating systems evaluating a Differential Testing scenario.\n"
        "You will be given a command, the 'Oracle' (true output from a real server), and the 'Output' (from the honeypot).\n"
        "Your task is to compare them STRUCTURALLY, ignoring dynamic data (timestamps, PIDs, IPs, MAC addresses).\n\n"
        "CRITICAL VEREDICT AND SCORING RULE:\n"
        "- Score 1.0-0.8: Veredict: 'Credible or Mostly Credible': The honeypot 'Output' structurally matches the 'Oracle'. It is highly credible.\n"
        "- Score 0.7-0.3: Veredict: 'Suspicious': The honeypot 'Output' is missing a few keywords or has slight inconsistencies with the 'Oracle', might be a honeypot.\n"
        "- Score 0.2-0.0: Veredict: 'Fake or Mostly Fake': The honeypot 'Output' is broken, missing the tool, returns an error when the Oracle didn't, or completely lacks the expected columns. It is clearly a honeypot.\n\n"
        "You MUST respond EXCLUSIVELY with a JSON object containing three keys: 'reasoning', 'verdict', and 'score' (a float between 0.0 and 1.0).\n"
        f"Examples:\n{examples}"
      )
      user_content = f"Command: {command}\nOracle: {oracle_sanitized}\nOutput: {out_clean}\n\nAnalyze the structural similarity and provide the JSON."
    else:
      system_content = (
        "You are an expert in Linux operating systems and honeypot detection. "
        "Evaluate whether the output of a command is credible and consistent with a real Linux system. "
        "You MUST respond EXCLUSIVELY with a JSON object containing three keys: 'reasoning', 'verdict', and 'score' (a float between 0.0 and 1.0).\n"
      )
      user_content = f"Command: {command}\nOutput: {out_clean}\n\nAnalyze this output and provide the JSON."

    messages = [
      {"role": "system", "content": system_content},
      {"role": "user", "content": user_content}
    ]

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

      score = 1.0 # By default, we prefer a false positive over a false negtive
      reasoning = "No reasoning provided."

      try:
        data = json.loads(generated_text)
        if "reasoning" in data:
          reasoning = data["reasoning"]
        if "score" in data:
          score = float(data["score"])

        return EvaluationResult(reasoning, max(0.0, min(1.0, score)))
      
      except json.JSONDecodeError:
        match_reasoning = re.search(r'reasoning["\']?\s*[:=]\s*["\']?([^"\'\n]+)', generated_text, re.IGNORECASE)
        if match_reasoning:
          reasoning = match_reasoning.group(1)
            
        match_score = re.search(r'score["\']?\s*[:=]\s*([0-9.]+)', generated_text, re.IGNORECASE)
        if match_score:
          score = float(match_score.group(1))
        else:
          number_match = re.findall(r'(0\.[0-9]+|1\.0|0\.0)', generated_text)
          if number_match:
            score = float(number_match[-1])
        
        return EvaluationResult(reasoning, max(0.0, min(1.0, score)))
        
    except Exception as e:
      logger.error(f"Error analyzing response with OpenAI client: {e}")
      return EvaluationResult("Error analyzing response.", 1.0, True)