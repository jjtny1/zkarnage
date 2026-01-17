from eth_abi import encode
from abc import ABC, abstractmethod

class ABIProvider(ABC):

    @abstractmethod
    def get_extcodesize_attack_data(self, contract_targets) -> str:
        pass

    @abstractmethod
    def get_jumpdest_attack_data(self) -> str:
        pass

    @abstractmethod
    def get_mcopy_attack_data(self) -> str:
        pass

    @abstractmethod
    def get_calldatacopy_attack_data(self, size) -> str:
        pass

    @abstractmethod
    def get_modexp_attack_data(self) -> str:
        pass

    @abstractmethod
    def get_bnpairing_attack_data(self) -> str:
        pass

    @abstractmethod
    def get_bnmult_attack_data(self) -> str:
        pass

    @abstractmethod
    def get_ecrecover_attack_data(self) -> str:
        pass

    @abstractmethod
    def get_keccak_attack_data(self, data_size) -> str:
        pass

    @abstractmethod
    def get_sha256_attack_data(self, data_size) -> str:
        pass

class ZKaranageGasTargetABIProvider:
	def __init__(self, gas_target: int):
		self.gas_target = gas_target

	def get_extcodesize_attack_data(self, contract_targets):
		encoded_data = encode(['uint256', 'address[]'], [self.gas_target, contract_targets])
		function_selector = Web3.keccak(text="executeExtCodesizeAttack(uint256,address[])").hex()[0:10]  # 0x + 8 chars (4 bytes)
		return function_selector + encoded_data.hex()

	def get_jumpdest_attack_data(self):
		encoded_data = encode(['uint256'], [self.gas_target])
		function_selector = Web3.keccak(text="executeJumpdestAttack(uint256)").hex()[0:10]  # 0x + 8 chars (4 bytes)
		return function_selector + encoded_data.hex()

	def get_mcopy_attack_data(self):
		encoded_data = encode(['uint256'], [self.gas_target])
		function_selector = Web3.keccak(text="executeMcopyAttack(uint256)").hex()[0:10]  # 0x + 8 chars (4 bytes)
		return function_selector + encoded_data.hex()

	def get_calldatacopy_attack_data(self, size):
		encoded_data = encode(['uint256', 'uint256'], [size, self.gas_target])
		function_selector = Web3.keccak(text="executeCalldatacopyAttack(uint256,uint256)").hex()[0:10]  # 0x + 8 chars (4 bytes)
		return function_selector + encoded_data.hex()

	def get_modexp_attack_data(self):
		encoded_data = encode(['uint256'], [self.gas_target])
		function_selector = Web3.keccak(text="executeModExpAttack(uint256)").hex()[0:10]  # 0x + 8 chars (4 bytes)
		return function_selector + encoded_data.hex()

	def get_bnpairing_attack_data(self):
		encoded_data = encode(['uint256'], [self.gas_target])
		function_selector = Web3.keccak(text="executeBnPairingAttack(uint256)").hex()[0:10]  # 0x + 8 chars (4 bytes)
		return function_selector + encoded_data.hex()

	def get_bnmult_attack_data(self):
		encoded_data = encode(['uint256'], [self.gas_target])
		function_selector = Web3.keccak(text="executeBnMulAttack(uint256)").hex()[0:10]  # 0x + 8 chars (4 bytes)
		return function_selector + encoded_data.hex()

	def get_ecrecover_attack_data(self):
		encoded_data = encode(['uint256'], [self.gas_target])
		function_selector = Web3.keccak(text="executeEcrecoverAttack(uint256)").hex()[0:10]  # 0x + 8 chars (4 bytes)
		return function_selector + encoded_data.hex()

	def get_keccak_attack_data(self, data_size):
		encoded_data = encode(['uint256', 'uint256'], [self.gas_target, data_size])
		function_selector = Web3.keccak(text="executeKeccakAttack(uint256,uint256)").hex()[0:10]  # 0x + 8 chars (4 bytes)
		return function_selector + encoded_data.hex()

	def get_sha256_attack_data(self, data_size):
		encoded_data = encode(['uint256', 'uint256'], [self.gas_target, data_size])
		function_selector = Web3.keccak(text="executeSha256Attack(uint256,uint256)").hex()[0:10]  # 0x + 8 chars (4 bytes)
		return function_selector + encoded_data.hex()

