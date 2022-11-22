package io.helidon.security.providers.httpauth;

import java.security.Security;
import java.util.Arrays;

import com.oracle.pic.commons.crypto.JCEProviders;

class SecurityProvider {
    static void loadBCFIPS() {
        Security.setProperty("keystore.type", "BCFKS");
        System.setProperty("useBcJsseProvider", "false");
        System.setProperty("javax.net.ssl.trustStoreType", "jks");
        System.out.println("Before JCEProviders.load(), security providers are: " + Arrays.toString(Security.getProviders()));
        JCEProviders.load();
        System.out.println("After JCEProviders.load(), security providers are: " + Arrays.toString(Security.getProviders()));
    }
}
