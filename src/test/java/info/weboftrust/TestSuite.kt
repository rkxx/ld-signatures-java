package info.weboftrust

import org.junit.platform.suite.api.SelectPackages
import org.junit.platform.suite.api.Suite

class TestSuite {
    @Suite
    @SelectPackages(
        "info.weboftrust.ldsignatures"
    )
    class TestSuite
}