import os
import tempfile
import unittest

import bchoc


class TestCrypto(unittest.TestCase):
    def test_case_id_roundtrip(self):
        case_id = "550e8400-e29b-41d4-a716-446655440000"
        encrypted = bchoc.encrypt_case_id(case_id)
        decrypted = bchoc.decrypt_field(encrypted, is_uuid=True)
        self.assertEqual(decrypted, case_id)

    def test_item_id_roundtrip(self):
        item_id = "123"
        encrypted = bchoc.encrypt_item_id(item_id)
        decrypted = bchoc.decrypt_field(encrypted, is_uuid=False)
        self.assertEqual(decrypted, int(item_id))

    def test_pad_field_length(self):
        padded = bchoc.pad_field("ABC", 12)
        self.assertEqual(len(padded), 12)
        self.assertTrue(padded.startswith(b"ABC"))


class TestLedger(unittest.TestCase):
    def test_genesis_block_sane(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "blockchain.dat")
            with open(path, "wb") as handle:
                handle.write(bchoc.create_genesis_block())

            ok, err = bchoc.blockchain_is_sane(path)
            self.assertTrue(ok, msg=err)


if __name__ == "__main__":
    unittest.main()
