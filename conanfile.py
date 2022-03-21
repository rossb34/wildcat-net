from conans import ConanFile, CMake, tools


class NetConan(ConanFile):
    name = "wildcat-net"
    version = "0.1.0"
    license = "MIT"
    author = "<Ross Bennett> <rossbennett34@gmail.com>"
    url = "https://github.com/rossb34/wildcat-net"
    description = "Network Library"
    exports_sources = "include/*"
    no_copy_source = True

    def package(self):
        self.copy("*.hpp")

    def package_id(self):
        self.info.header_only()
