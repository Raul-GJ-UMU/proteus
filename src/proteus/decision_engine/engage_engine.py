from src.proteus.decision_engine.engage_parser import EngageParser
from src.proteus.decision_engine.engage_mapping import TechniqueMapping
from src.proteus.decision_engine.deception_capabilities import DeceptionCapabilites

from loguru import logger

logger.add("logs/proteus_engage_engine.log", rotation="10 MB")

class EngageEngine:
  def __init__(self, vfs, virtual_shell):
    self.vfs = vfs
    self.virtual_shell = virtual_shell
    self.engage_parser = EngageParser()
    self.deception_capabilities = DeceptionCapabilites()
    self.session_state = {
      "deceptions_deployed": [],
      "engage_techniques": [],
    }
  
  def execute_deception(self, capability_name: str) -> None:
    if not hasattr(self.deception_capabilities, capability_name):
      logger.warning(f"The AI hallucinated the capability: {capability_name}. Ignoring.")
      return
    
    function = getattr(self.deception_capabilities, capability_name)
    result = function(self.vfs, self.virtual_shell)
    logger.success(f"Executed deception capability: {capability_name}")