"""Package the existing hook resolver from its single source, without vendoring."""
from setuptools import setup
from setuptools.command.build_py import build_py


class BuildPy(build_py):
    def find_package_modules(self, package, package_dir):
        modules = super().find_package_modules(package, package_dir)
        if package == "fleet_guards":
            modules.append((package, "_datadir", "tools/datadir.py"))
        return modules


setup(cmdclass={"build_py": BuildPy})
