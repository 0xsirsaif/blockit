import pytest

from blockit.crypto_algorithms import MatrixEncryption, ShiftEncryption


class TestShiftEncryption:
    @pytest.mark.parametrize("text, expected", [("Hello World!", "Khoor Zruog!"), ("ZZZZZZZ", "CCCCCCC")])
    def test_shift_3_encryption(self, text, expected):
        shift_3_encryption = ShiftEncryption()
        assert shift_3_encryption.encrypt(text) == expected

    @pytest.mark.parametrize("text, expected", [("Khoor Zruog!", "Hello World!"), ("CCCCCC", "ZZZZZZ")])
    def test_shift_3_decryption(self, text, expected):
        shift_3_encryption = ShiftEncryption()
        assert shift_3_encryption.decrypt(text) == expected

    @pytest.mark.parametrize("text, expected", [("Hello World!", "Lipps Asvph!"), ("ZZZZZZ", "DDDDDD")])
    def test_shift_4_encryption(self, text, expected):
        shift_4_encryption = ShiftEncryption(shift=4)
        assert shift_4_encryption.encrypt(text) == expected

    @pytest.mark.parametrize("text, expected", [("Lipps Asvph!", "Hello World!"), ("DDDDDD", "ZZZZZZ")])
    def test_shift_4_decryption(self, text, expected):
        shift_4_encryption = ShiftEncryption(shift=4)
        assert shift_4_encryption.decrypt(text) == expected

    def test_apply_shift_cipher(self):
        shift_3_encryption = ShiftEncryption()
        assert shift_3_encryption.apply_shift_cipher("Hello World!", "encrypt") == "Khoor Zruog!"
        assert shift_3_encryption.apply_shift_cipher("Khoor Zruog!", "decrypt") == "Hello World!"
        assert shift_3_encryption.apply_shift_cipher("ZZZZZZZ", "encrypt") == "CCCCCCC"
        assert shift_3_encryption.apply_shift_cipher("CCCCCCC", "decrypt") == "ZZZZZZZ"

        shift_4_encryption = ShiftEncryption(shift=4)
        assert shift_4_encryption.apply_shift_cipher("Hello World!", "encrypt") == "Lipps Asvph!"
        assert shift_4_encryption.apply_shift_cipher("Lipps Asvph!", "decrypt") == "Hello World!"
        assert shift_4_encryption.apply_shift_cipher("ZZZZZZZ", "encrypt") == "DDDDDDD"
        assert shift_4_encryption.apply_shift_cipher("DDDDDDD", "decrypt") == "ZZZZZZZ"


class TestMatrixEncryption:
    def test_padding_out_text(self):
        matrix_encryption = MatrixEncryption()
        assert matrix_encryption.padding_out_text("HELLO") == "HELLOXXXXXXXXXXX"
        assert matrix_encryption.padding_out_text("HELLOXXXXXXXXXXX") == "HELLOXXXXXXXXXXX"

    def test_convert_to_vector(self):
        matrix_encryption = MatrixEncryption()
        assert matrix_encryption.convert_to_vector("HELLO") == [[7, 4, 11, 11, 14]]
        assert matrix_encryption.convert_to_vector("WORLD") == [[22, 14, 17, 11, 3]]
        assert matrix_encryption.convert_to_vector("") == [[]]
        # only support A-Z, upper case
        with pytest.raises(ValueError):
            assert matrix_encryption.convert_to_vector("12345")
        with pytest.raises(ValueError):
            assert matrix_encryption.convert_to_vector("AaBbCc")

    def test_convert_to_block(self):
        matrix_encryption = MatrixEncryption()
        assert matrix_encryption.convert_to_block([[7, 4, 11, 11, 14]]) == "HELLO"
        assert matrix_encryption.convert_to_block([[22, 14, 17, 11, 3]]) == "WORLD"
        assert matrix_encryption.convert_to_block([[]]) == ""
        with pytest.raises(IndexError):
            assert matrix_encryption.convert_to_block([[49, 50, 51, 52, 53]])
        with pytest.raises(IndexError):
            assert matrix_encryption.convert_to_block([[65, 97, 66, 98, 67, 99]])

    @pytest.mark.parametrize(
        "digraph_vector, matrix, expected_result",
        [
            ([[1, 2, 3]], [[1, 2, 3], [4, 5, 6], [7, 8, 9]], [[4, 10, 16]]),
            ([[10, 20, 30]], [[1, 2, 3], [4, 5, 6], [7, 8, 9]], [[14, 22, 4]]),
        ],
    )
    def test_valid_matrix_multiply(self, digraph_vector, matrix, expected_result):
        matrix_encryption = MatrixEncryption()
        assert matrix_encryption.matrix_multiply(digraph_vector, matrix) == expected_result

    @pytest.mark.parametrize(
        "digraph_vector, matrix",
        [
            ([[]], [[1, 2, 3], [4, 5, 6], [7, 8, 9]]),
            ([[10, 20, 30]], [[1, 2, 3], [4, 5, 6]]),
        ],
    )
    def test_invalid_matrix_multiply(self, digraph_vector, matrix):
        with pytest.raises(ValueError):
            matrix_encryption = MatrixEncryption()
            matrix_encryption.matrix_multiply(digraph_vector, matrix)

    # -- RED TESTS --
    # TODO:
    def test_encrypt(self):
        matrix_encryption = MatrixEncryption()
        assert matrix_encryption.encrypt("HELLO") == "XINEAACGNUNDOHLL"
        assert matrix_encryption.encrypt("WORLD") == "WDIHMGZEYIMFGOQS"

    def test_decrypt(self):
        matrix_encryption = MatrixEncryption()
        assert matrix_encryption.decrypt("XINEAACGNUNDOHLL") == "HELLO"
        assert matrix_encryption.decrypt("WDIHMGZEYIMFGOQS") == "WORLD"
