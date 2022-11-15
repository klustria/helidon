package io.helidon.security.providers.httpsign;

import java.security.Security;
import java.util.Arrays;

import com.oracle.pic.commons.crypto.JCEProviders;

class SecurityProvider {
    static void loadJipher() {
        System.setProperty("javax.net.ssl.trustStoreType", "jks");
        System.setProperty("useJipherJceProvider", "true");
        System.out.println("Before JCEProviders.load(), security providers are: " + Arrays.toString(Security.getProviders()));
        JCEProviders.load();
        System.out.println("After JCEProviders.load(), security providers are: " + Arrays.toString(Security.getProviders()));
    }
}
