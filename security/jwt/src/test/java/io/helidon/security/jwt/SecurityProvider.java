package io.helidon.security.jwt;

import java.security.Security;
import java.util.Arrays;

import com.oracle.pic.commons.crypto.JCEProviders;

public class SecurityProvider {
    public static void loadBCFIPS() {
        Security.setProperty("keystore.type", "BCFKS");
        System.setProperty("useBcJsseProvider", "false");
        System.out.println("Before JCEProviders.load(), security providers are: " + Arrays.toString(Security.getProviders()));
        JCEProviders.load();
        System.out.println("After JCEProviders.load(), security providers are: " + Arrays.toString(Security.getProviders()));
    }
}
