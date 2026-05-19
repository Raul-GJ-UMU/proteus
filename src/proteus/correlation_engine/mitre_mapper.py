import os
import pickle
import numpy as np
from loguru import logger
from openai import OpenAI
from dotenv import load_dotenv

import nltk
from nltk.tokenize import word_tokenize
from nltk.stem import WordNetLemmatizer, porter

from src.proteus.telemetry.models import MitreMapping

CONFIDENCE_THRESHOLD = 0.2

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

class MitreMapper:
  def __init__(self):
    self.classifier = None
    self.vectorizer = None
    self.is_loaded = False
    
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

  def _generate_cti_sentence(self, command: str) -> str:
    if not self.llm_client.api_key:
      raise ValueError("OPENAI_API_KEY not configured in the .env file")

    prompt = (
      "Given the following command executed in a terminal by an attacker, "
      "generate a brief sentence that describes the attack. "
      "Try to use words in a way that the automatic mapping to MITRE ATT&CK is accurate. "
      "Example: 'Adversaries may abuse command and script interpreters to execute commands.' "
      f"Command: {command}"
    )

    if not self.llm_model:
      logger.error("OPENAI_MODEL not configured in the .env file. Cannot generate CTI sentence.")
      return ""
    
    response = self.llm_client.chat.completions.create(
      model=self.llm_model,
      messages=[
        {"role": "system", "content": "You are a Cyber Threat Intelligence expert."},
        {"role": "user", "content": prompt}
      ],
      temperature=0.1,
      max_tokens=50
    )

    if not response.choices or not response.choices[0].message.content:
      logger.error("Unexpected response from OpenAI: No content received in the response.")
      return ""
    
    raw_text = response.choices[0].message.content.strip()
    clean_sentence = raw_text.split('\n')[0].strip()
    clean_sentence = clean_sentence.replace('"', '').replace("'", "")
    
    return clean_sentence

  def evaluate_command(self, command: str):
    if not self.is_loaded or not command.strip():
      return None

    if not self.classifier or not self.vectorizer:
      logger.error("The MITRE model is not completely loaded. Cannot evaluate the command.")
      return None
    
    try:
      cti_sentence = self._generate_cti_sentence(command)
      logger.debug(f"Generated CTI sentence: {cti_sentence}")
      
      word_list = word_tokenize(cti_sentence)
      lemmatized_list = [self.lemmatizer.lemmatize(w) for w in word_list]
      stemmed_list = [self.ps.stem(w) for w in lemmatized_list]
      preprocessed_text = ' '.join(stemmed_list)
      
      text_vectorized = self.vectorizer.transform([preprocessed_text])
      probabilities = self.classifier.predict_proba(text_vectorized)
      
      top_index = np.argsort(probabilities[0])[-1]
      top_label = self.classifier.classes_[top_index]
      top_confidence = probabilities[0][top_index]

      if top_confidence < CONFIDENCE_THRESHOLD:
        return None

      mitre_mapping = MitreMapping(
        technique_id=top_label,
        confidence=round(float(top_confidence), 3),
        cti_sentence=cti_sentence
      )
      return mitre_mapping
        
    except Exception as e:
      logger.error(f"Error in live MITRE prediction: {e}")
      return None