from conan import ConanFile
from conan.tools.cmake import CMake, CMakeDeps, CMakeToolchain, cmake_layout


class PkgRecipe(ConanFile):
    name = "blf_converter"
    version = "0.1"
    package_type = "application"

    # Binary configuration
    settings = "os", "compiler", "build_type", "arch"

    # Sources are located in the same place as this recipe, copy them to the recipe
    exports_sources = "CMakeLists.txt", "src/*"

    def layout(self):
        cmake_layout(self, "Ninja")

    def requirements(self):
        self.requires("libpcap/1.10.5")
        self.requires("zstd/1.5.7")
        self.requires("taywee-args/6.4.6")
        self.requires("tinyxml2/11.0.0")

    def configure(self):
        self.options["libpcap"].shared = False
        self.options["zstd"].shared = False
        self.options["taywee-args"].shared = False
        self.options["tinyxml2"].shared = False

    def generate(self):
        deps = CMakeDeps(self)
        deps.generate()
        tc = CMakeToolchain(self)
        tc.generate()

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def package(self):
        cmake = CMake(self)
        cmake.install()
