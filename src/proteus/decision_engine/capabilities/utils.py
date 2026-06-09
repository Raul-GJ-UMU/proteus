class CapabilityResult:
  def __init__(self, success: bool, eac_id: str, function_name: str, message: str = ""):
    self.success = success
    self.eac_id = eac_id
    self.function_name = function_name
    self.message = message