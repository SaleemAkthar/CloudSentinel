# Master test runner — executes all test modules in the project.
# Run from the project root:
#   python -m tests.run_all

import unittest
import sys
import time


def build_suite() -> unittest.TestSuite:
    """Loads and combines all test modules into a single suite."""
    loader = unittest.TestLoader()
    suite  = unittest.TestSuite()

    modules = [
        ("tests.test_online_stats", "core statistical math"),
        ("tests.test_severity",     "severity classification"),
        # ("tests.test_data_pipeline", "data pipeline"),  # uncomment when ready
    ]

    for module_path, label in modules:
        try:
            module = __import__(module_path, fromlist=[""])
            suite.addTests(loader.loadTestsFromModule(module))
            print(f"[✔] Loaded: {module_path}  ({label})")
        except ImportError as e:
            print(f"[✘] Could not load {module_path}: {e}")

    return suite


def run() -> None:
    """Runs the full suite and prints a pass/fail summary."""
    print()
    print("=" * 55)
    print("  Cloud Sentinel — Full Test Suite")
    print("=" * 55)

    suite = build_suite()
    print(f"\n{suite.countTestCases()} test(s) discovered.\n")
    print("-" * 55)

    runner  = unittest.TextTestRunner(verbosity=2, stream=sys.stdout)
    start   = time.time()
    result  = runner.run(suite)
    elapsed = round(time.time() - start, 2)

    print()
    print("=" * 55)
    print(f"  Ran:      {result.testsRun}")
    print(f"  Passed:   {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"  Failed:   {len(result.failures)}")
    print(f"  Errors:   {len(result.errors)}")
    print(f"  Time:     {elapsed}s")
    print()

    if result.wasSuccessful():
        print("  ✅  All tests passed — safe to commit.")
        sys.exit(0)
    else:
        print("  ❌  Tests failed — do not commit until resolved.")
        for test, tb in result.failures + result.errors:
            print(f"    • {test}: {tb.strip().splitlines()[-1]}")
        sys.exit(1)


if __name__ == "__main__":
    run()
