plugins {
    java
}

dependencies {
    compileOnly(project(":modules:cesecore-common"))
    compileOnly(libs.jakarta.xml.ws.api)
    compileOnly(libs.bcpkix)
    compileOnly(libs.bcprov)
    compileOnly(libs.bctls)
    compileOnly(libs.bcutil)
    compileOnly(libs.log4j.v12.api)
    compileOnly(libs.commons.lang)
    compileOnly(libs.commons.lang3)
    compileOnly(libs.commons.configuration2)
    compileOnly(libs.x509.common.util)
    compileOnly(libs.cryptotokens.api)
    compileOnly(libs.cryptotokens.impl) 
    compileOnly(libs.jakarta.persistence.api)
}

sourceSets {
    val main by getting {
        java {
            setSrcDirs(
                listOf("src")
            )
        }
    }
}

tasks.jar {
    from(sourceSets["main"].output)
}
