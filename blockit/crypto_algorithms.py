import sys
from abc import ABC, abstractmethod


class CryptoAlgorithm(ABC):
    @abstractmethod
    def encrypt(self, text):
        ...

    @abstractmethod
    def decrypt(self, text):
        ...


class ShiftEncryption(CryptoAlgorithm):
    """
    This class provides shift encryption and decryption functionality using the shift cipher algorithm.
    """

    def __init__(self, shift: int = 3):
        self.shift = shift
        self.alphabet_size = 26

    def apply_shift_cipher(self, text: str, method: str) -> str:
        """
        Applies the shift cipher algorithm to the given text based on the specified method.
        :param text: The text to be encrypted or decrypted.
        :param method: The method to be applied, either "encrypt" or "decrypt".
        :return: The encrypted or decrypted text.

        To run the doctests: pytest --doctest-modules -vvs <filename>.py

        >>> shift_3_encryption = ShiftEncryption()
        >>> shift_3_encryption.apply_shift_cipher("Hello World!", "encrypt")
        'Khoor Zruog!'
        >>> shift_3_encryption.apply_shift_cipher("Khoor Zruog!", "decrypt")
        'Hello World!'
        >>> shift_3_encryption.apply_shift_cipher("ZZZZZZZ", "encrypt")
        CCCCCCC
        >>> shift_3_encryption.apply_shift_cipher("CCCCCC", "decrypt")
        ZZZZZZ
        >>> shift_4_encryption = ShiftEncryption(shift=4)
        >>> shift_4_encryption.apply_shift_cipher("Hello World!", "encrypt")
        'Lipps Asvph!'
        >>> shift_4_encryption.apply_shift_cipher("Lipps Asvph!", "decrypt")
        'Hello World!'
        >>> shift_4_encryption.apply_shift_cipher("ZZZZZZZ", "encrypt")
        DDDDDDD
        >>> shift_4_encryption.apply_shift_cipher("DDDDDDD", "decrypt")
        ZZZZZZZ
        """
        chars: list = []
        for char in text:
            if char.isalpha():
                base: int = ord("A") if char.isupper() else ord("a")
                if method == "encrypt":
                    char: str = chr(
                        (ord(char) - base + self.shift) % self.alphabet_size + base
                    )
                else:
                    char: str = chr(
                        (ord(char) - base - self.shift) % self.alphabet_size + base
                    )
            chars.append(char)
        return "".join(chars)

    def encrypt(self, text: str) -> str:
        """
        Encrypts the given text using the shift cipher algorithm.
        :param text: The text to be encrypted.
        :return: The encrypted text.
        """
        return self.apply_shift_cipher(text, method="encrypt")

    def decrypt(self, encrypted_text) -> str:
        """
        Decrypts the given text using the shift cipher algorithm.
        :param encrypted_text: The text to be decrypted.
        :return: The decrypted text.
        """
        return self.apply_shift_cipher(encrypted_text, method="decrypt")


class CryptoAlgorithmFactory:
    @staticmethod
    def create_algorithm(algorithm_name, **kwargs):
        if algorithm_name == "shift":
            shift = kwargs.get("shift", 0)
            return ShiftEncryption(shift)


def main():
    if len(sys.argv) < 4:
        print("Usage: lockit <str> <crypto-algorithm> <encrypt or decrypt>")
        return

    text = sys.argv[1]
    algorithm_name = sys.argv[2]
    operation = sys.argv[3]

    crypto_algorithm = CryptoAlgorithmFactory.create_algorithm(algorithm_name)
    if operation == "encrypt":
        encrypted_text = crypto_algorithm.encrypt(text)
        print(f"Encrypted text: {encrypted_text}")
    elif operation == "decrypt":
        decrypted_text = crypto_algorithm.decrypt(text)
        print(f"Decrypted text: {decrypted_text}")
    else:
        print("Invalid operation. Use 'encrypt' or 'decrypt'")


if __name__ == "__main__":
    main()
