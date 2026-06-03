import os
import re
import pickle
import numpy as np
from loguru import logger
from openai import OpenAI
from dotenv import load_dotenv

import nltk
from nltk.tokenize import word_tokenize
from nltk.stem import WordNetLemmatizer, porter

from pydantic import BaseModel, Field

from src.proteus.telemetry.models import MitreMapping

CONFIDENCE_THRESHOLD = 0.3

logger.add("logs/proteus_mitre_mapper.log", rotation="10 MB")

load_dotenv()

try:
  nltk.data.find('tokenizers/punkt')
  nltk.data.find('tokenizers/punkt_tab')
  nltk.data.find('corpora/wordnet')
except LookupError:
  nltk.download('punkt', quiet=True)
  nltk.download('punkt_tab', quiet=True)
  nltk.download('wordnet', quiet=True)

class Phase(BaseModel):
  commands_indexes: str = Field(..., description="Comma-separated indexes of the commands in the history that belong to this phase")
  cti_sentence: str = Field(..., description="The CTI sentence describing the adversary's action for this phase")


class MitreMapper:
  def __init__(self):
    self.classifier = None
    self.vectorizer = None
    self.is_loaded = False
    self.command_history = []
    
    self.lemmatizer = WordNetLemmatizer()
    self.ps = porter.PorterStemmer()

    self.llm_client = OpenAI(
      base_url=os.getenv("OPENAI_BASE_URL"),
      api_key=os.getenv("OPENAI_API_KEY")
    )
    self.llm_model = os.getenv("OPENAI_MODEL")
    
    self._load_models()

  def _load_models(self):
    try:
      base_dir = os.path.dirname(os.path.abspath(__file__))
      model_path = os.path.join(base_dir, "mapper", "ml_model", "MLP_classifier.sav") 
      
      if os.path.exists(model_path):
        with open(model_path, 'rb') as model_file:
          self.vectorizer, self.classifier = pickle.load(model_file)
        self.is_loaded = True
        logger.success("Correlation engine loaded successfully.")
      else:
        logger.error(f"Model file not found: {model_path}")
    except Exception as e:
      logger.error(f"Error loading MITRE model: {e}")
  
  def generate_attack_phases(self, history: list[str]) -> list[Phase]:
    if not history:
      return []
    
    if not self.llm_client.api_key:
      raise ValueError("OPENAI_API_KEY not configured in the .env file")
    
    history_text = "\n".join([f"[{i+1}] {cmd}" for i, cmd in enumerate(history)])

    system_prompt = "Group the bash commands into phases. Answer ONLY with one line per phase using the exact format: [Numbers] Adversaries may <description>."

    if not self.llm_model:
      logger.error("OPENAI_MODEL not configured in the .env file. Cannot generate CTI sentence.")
      return []
    
    try:
      response = self.llm_client.chat.completions.create(
        model=self.llm_model,
        messages = [
          {"role": "system", "content": system_prompt},
          {"role": "user", "content": "History:\n[1] whoami\n[2] id\n[3] cat /etc/passwd"},
          {"role": "assistant", "content": "[1, 2] Adversaries may attempt to identify the primary user, currently logged in user, set of users that commonly uses a system, or whether a user is actively using the system.\n[3] Adversaries may attempt to dump credentials to obtain account login and credential material."},
          {"role": "user", "content": f"History:\n{history_text}"}
        ],
        temperature=0.1,
        max_tokens=200
      )
      raw_output = response.choices[0].message.content
      if not raw_output:
        logger.error("Unexpected response from OpenAI: No content received in the response.")
        return []
      raw_output = raw_output.strip()
      logger.debug(f"Raw output from command history evaluation:\n{raw_output}")

      return self.parse_llm_phrases(raw_output)
    except Exception as e:
      logger.error(f"Error evaluating command history with LLM: {e}")
      return []
    
  def parse_llm_phrases(self, raw_output: str) -> list[Phase]:
    phases: list[Phase] = []
    pattern = r"\[?(.*?)\]?[:\-]*\s*(Adversaries may[^\n]+)"
    matches = re.findall(pattern, raw_output, re.IGNORECASE)

    for match in matches:
      indexes_str = match[0].strip()
      sentence = match[1].strip()
      clean_sentence = sentence.split('\n')[0].strip()
      clean_sentence = clean_sentence.replace('"', '').replace("'", "")

      phases.append(Phase(
        commands_indexes=indexes_str,
        cti_sentence=clean_sentence
      ))

    return phases

  def evaluate_command(self, command: str) -> list[MitreMapping] | None:
    if not self.is_loaded or not command.strip():
      return None

    if not self.classifier or not self.vectorizer:
      logger.error("The MITRE model is not completely loaded. Cannot evaluate the command.")
      return None
    
    try:
      self.command_history.append(command)
      cti_phases = self.generate_attack_phases(self.command_history)
      logger.debug(f"Generated CTI phases: {cti_phases}")
      
      if not cti_phases:
        return None
      
      mappings: list[MitreMapping] = []
      
      for phase in cti_phases:
        command_indexes = phase.commands_indexes
        cti_sentence = phase.cti_sentence

        word_list = word_tokenize(cti_sentence)
        lemmatized_list = [self.lemmatizer.lemmatize(w) for w in word_list]
        preprocessed_text = ' '.join(lemmatized_list)
        text_vectorized = self.vectorizer.transform([preprocessed_text])
        probabilities = self.classifier.predict_proba(text_vectorized)

        top_index = np.argsort(probabilities[0])[-1]
        top_label = self.classifier.classes_[top_index]
        top_confidence = probabilities[0][top_index]

        if top_confidence < CONFIDENCE_THRESHOLD:
          logger.warning(f"Low confidence ({top_confidence:.3f}) for command '{command}' with predicted technique '{top_label}'. Skipping MITRE mapping.")
          continue

        mitre_mapping = MitreMapping(
          command_indexes=command_indexes,
          technique_id=top_label,
          confidence=round(float(top_confidence), 3),
          cti_sentence=cti_sentence
        )
        mappings.append(mitre_mapping)
      
      return mappings
        
    except Exception as e:
      logger.error(f"Error in live MITRE prediction: {e}")
      return None