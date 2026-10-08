"""Map the canonical guard tools into the wheel without a second source copy."""
from setuptools import setup
from setuptools.command.build_py import build_py


class BuildCanonicalTools(build_py):
    def find_package_modules(self, package, package_dir):
        modules = super().find_package_modules(package, package_dir)
        if package == "fleet_guards._canonical":
            names = {"datadir", "data_boundary", "pii_guard", "storage_contract"}
            return [row for row in modules if row[1] in names]
        return modules


setup(cmdclass={"build_py": BuildCanonicalTools})
