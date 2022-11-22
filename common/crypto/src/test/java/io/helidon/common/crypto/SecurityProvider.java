package io.helidon.common.crypto;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

import com.google.common.base.Preconditions;
import com.oracle.pic.commons.crypto.JCEProviders;
import org.bouncycastle.crypto.CryptoServicesRegistrar;

class SecurityProvider {
    static void loadBCFIPS() {
        Security.setProperty("keystore.type", "BCFKS");
        System.setProperty("useBcJsseProvider", "false");
        System.out.println("Before JCEProviders.load(), security providers are: " + Arrays.toString(Security.getProviders()));
        JCEProviders.load();
        System.out.println("After JCEProviders.load(), security providers are: " + Arrays.toString(Security.getProviders()));
    }

    private static final String FIPS_APPROVED_ONLY_PROPERTY = "org.bouncycastle.fips.approved_only";
    public static final String BC_FIPS_KEYSTORE_TYPE = "BCFKS";
    public static final String BC_FIPS_PROVIDER_NAME = "BCFIPS";
    private static final String JAVAX_KEYSTORE_TYPE_PROPERTY = "javax.net.ssl.keyStoreType";
    private static final String SSL_KEY_STORE_TYPE = "ssl.keystore.type";
    private static final String KEY_STORE_TYPE = "keystore.type";
    private static final String SUN_JSSE_PROVIDER_CLASSNAME = "com.sun.net.ssl.internal.ssl.Provider";

    static void loadCustomBCFIPS() {
        // For Java 9 or later, if your application uses a JKS format truststore, such as the default
        // Java truststore, set the javax.net.ssl.trustStoreType system property to jks. See the Jipher
        // Troubleshooting Guide for more details. Otherwise, remove this line if the truststore used by
        // the application is in PKCS12 format or if truststore is not used at all.
        System.setProperty("javax.net.ssl.trustStoreType", "jks");

        // Set Bouncy Castle FIPS to FIPS approved-mode and register it at the top of the security provider list.
        setSystemAndSecurityProperty("FIPS_APPROVED_ONLY_PROPERTY", "true");

        SecureRandom entropySource = null;

        try {
            entropySource = SecureRandom.getInstance("NativePRNGNonBlocking", "SUN");
        } catch(NoSuchProviderException | NoSuchAlgorithmException e) {
            // entropySource = new SecureRandom();
            System.out.println("enctropySource error " + e);
        }
        Security.insertProviderAt(new org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider(null, entropySource), 1);

        if (isClassFound(SUN_JSSE_PROVIDER_CLASSNAME)) {
            // Replace (default) SunJSSE provider with SunJSSE provider
            // configured to use BCFIPS as its sole FIPS JCE provider
            Security.removeProvider("SunJSSE");

            // Set various system and security keystore type properties to BCFKS
            Security.setProperty(KEY_STORE_TYPE, BC_FIPS_KEYSTORE_TYPE);
            setSystemAndSecurityProperty(JAVAX_KEYSTORE_TYPE_PROPERTY, BC_FIPS_KEYSTORE_TYPE);
            setSystemAndSecurityProperty(SSL_KEY_STORE_TYPE, BC_FIPS_KEYSTORE_TYPE);

            final Provider sunJsseProvider = createJsseProvider(SUN_JSSE_PROVIDER_CLASSNAME, BC_FIPS_PROVIDER_NAME);

            // When the SunJSSE provider is configured with a FIPS JCE provider
            // it does not add an alias from SSL > TLS. Add one for backwards compatibility.
            sunJsseProvider.put("Alg.Alias.SSLContext.SSL", "TLS");

            // Inserting immediately after the BCFIPS provider just prioritizes the provider over
            // others when going through the default list getting provider by name will return that
            // provider regardless of the position of the provider in the list
            Security.insertProviderAt(sunJsseProvider, 2);
        }

        Preconditions.checkArgument(
                CryptoServicesRegistrar.setApprovedOnlyMode(true),
                "Requires approved mode for compliance.");
        System.out.println("Custom: After JCEProviders.load(), security providers are: " + Arrays.toString(Security.getProviders()));
    }

    private static void setSystemAndSecurityProperty(String name, String value) {
        System.setProperty(name, value);
        Security.setProperty(name, value);
    }

    private static boolean isClassFound(String className) {
        try {
            Class.forName(className, false, null);
        } catch (ClassNotFoundException e) {
            return false;
        }
        return true;
    }

    private static Provider createJsseProvider(String className, String providerName) {
        try {
            final Class<?> jsseClass = Class.forName(className);
            final Constructor<?> constructor = jsseClass.getConstructor(String.class);
            return (Provider) constructor.newInstance(providerName);
        } catch (ClassNotFoundException
                 | SecurityException
                 | InstantiationException
                 | InvocationTargetException
                 | NoSuchMethodException
                 | IllegalAccessException e) {
            throw new IllegalStateException("Unable to find the provider class : " + className, e);
        }
    }
}
