import unittest

from app.decision import decide_action


class DecideActionTests(unittest.TestCase):
    def test_allow_range_includes_zero_and_thirty(self) -> None:
        self.assertEqual(decide_action(0), "allow")
        self.assertEqual(decide_action(30), "allow")

    def test_deceive_range_includes_thirty_one_and_seventy(self) -> None:
        self.assertEqual(decide_action(31), "deceive")
        self.assertEqual(decide_action(70), "deceive")

    def test_block_range_includes_seventy_one_and_one_hundred(self) -> None:
        self.assertEqual(decide_action(71), "block")
        self.assertEqual(decide_action(100), "block")

    def test_rejects_scores_outside_zero_to_one_hundred(self) -> None:
        for score in (-1, 101):
            with self.subTest(score=score):
                with self.assertRaises(ValueError):
                    decide_action(score)


if __name__ == "__main__":
    unittest.main()
