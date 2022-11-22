package io.helidon.security.providers.httpsign;

import java.security.Security;
import java.util.Arrays;

import com.oracle.pic.commons.crypto.JCEProviders;

class SecurityProvider {
    static void loadBCFIPS() {
        Security.setProperty("keystore.type", "BCFKS");
        System.setProperty("useBcJsseProvider", "false");
        System.out.println("Before JCEProviders.load(), security providers are: " + Arrays.toString(Security.getProviders()));
        JCEProviders.load();
        System.out.println("After JCEProviders.load(), security providers are: " + Arrays.toString(Security.getProviders()));
    }
}
