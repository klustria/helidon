/*
 * Copyright (c) 2019, 2020 Oracle and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.helidon.grpc.server;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.Provider;
import java.security.Security;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;
import java.util.stream.Stream;

import javax.net.ssl.SSLException;

import io.helidon.common.LogConfig;
import io.helidon.common.configurable.Resource;
import io.helidon.config.Config;
import io.helidon.config.ConfigSources;
import io.helidon.grpc.core.GrpcTlsDescriptor;
import io.helidon.grpc.server.test.Echo;
import io.helidon.grpc.server.test.EchoServiceGrpc;

import com.google.common.base.Preconditions;
import com.oracle.bedrock.runtime.LocalPlatform;
import com.oracle.bedrock.runtime.network.AvailablePortIterator;
import io.grpc.Channel;
import io.grpc.ManagedChannel;
import io.grpc.StatusRuntimeException;
import io.grpc.netty.GrpcSslContexts;
import io.grpc.netty.NegotiationType;
import io.grpc.netty.NettyChannelBuilder;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.junit.AfterClass;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import services.EchoService;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

/**
 * Tests for gRPC server with SSL connections
 */
public class SslITTest {

    // ----- data members ---------------------------------------------------

    /**
     * The {@link java.util.logging.Logger} to use for logging.
     */
    private static final Logger LOGGER = Logger.getLogger(SslITTest.class.getName());

    /**
     * The Helidon {@link GrpcServer} being tested.
     */
    private static GrpcServer grpcServer_1WaySSL;

    /**
     * The Helidon {@link GrpcServer} being tested.
     */
    private static GrpcServer grpcServer_2WaySSL;

    /**
     * The Helidon {@link GrpcServer} being tested.
     */
    private static GrpcServer grpcServer_2WaySSLConfig;

    private static final String CLIENT_CERT = "ssl/clientCert.pem";
    private static final String CLIENT_KEY  = "ssl/clientKey.pem";
    private static final String CA_CERT     = "ssl/ca.pem";
    private static final String SERVER_CERT = "ssl/serverCert.pem";
    private static final String SERVER_KEY  = "ssl/serverKey.pem";

    private static final String FIPS_APPROVED_ONLY_PROPERTY = "org.bouncycastle.fips.approved_only";
    public static final String BC_FIPS_KEYSTORE_TYPE = "BCFKS";
    public static final String BC_FIPS_PROVIDER_NAME = "BCFIPS";
    private static final String JAVAX_KEYSTORE_TYPE_PROPERTY = "javax.net.ssl.keyStoreType";
    private static final String SSL_KEY_STORE_TYPE = "ssl.keystore.type";
    private static final String KEY_STORE_TYPE = "keystore.type";
    private static final String SUN_JSSE_PROVIDER_CLASSNAME = "com.sun.net.ssl.internal.ssl.Provider";

    // ----- test lifecycle -------------------------------------------------

    static {
        // For Java 9 or later, if your application uses a JKS format truststore, such as the default
        // Java truststore, set the javax.net.ssl.trustStoreType system property to jks. See the Jipher
        // Troubleshooting Guide for more details. Otherwise, remove this line if the truststore used by
        // the application is in PKCS12 format or if truststore is not used at all.
        System.setProperty("javax.net.ssl.trustStoreType", "jks");

        // Set Bouncy Castle FIPS to FIPS approved-mode and register it at the top of the security provider list.
        setSystemAndSecurityProperty(FIPS_APPROVED_ONLY_PROPERTY, "true");
        Security.insertProviderAt(new org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider(), 1);

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

    @BeforeAll
    public static void setup() throws Exception {
        LogConfig.configureRuntime();

        AvailablePortIterator ports = LocalPlatform.get().getAvailablePorts();

        int port1WaySSL = ports.next();
        int port2WaySSL = ports.next();
        int port2WaySSLConfig = ports.next();

        grpcServer_1WaySSL = startGrpcServer(port1WaySSL, false /*mutual*/, false /*useConfig*/);
        grpcServer_2WaySSL = startGrpcServer(port2WaySSL, true /*mutual*/, false /*useConfig*/);
        grpcServer_2WaySSLConfig = startGrpcServer(port2WaySSLConfig, true/*mutual*/, true /*useConfig*/);
    }

    @AfterClass
    public static void cleanup() throws Exception
    {
        CompletableFuture<?>[] futures =
                         Stream.of(grpcServer_1WaySSL, grpcServer_2WaySSL, grpcServer_2WaySSLConfig)
                        .map(server -> server.shutdown().toCompletableFuture())
                        .toArray(CompletableFuture<?>[]::new);

        CompletableFuture.allOf(futures).get(10, TimeUnit.SECONDS);
    }

    // ----- test methods ---------------------------------------------------

    @Test
    public void shouldConnectWithoutClientCertsFor1Way() throws Exception {
        Resource tlsCaCert = Resource.create(CA_CERT);

        // client do not have to provide certs for 1way ssl
        SslContext sslContext = clientSslContext(tlsCaCert, null, null);

        Channel channel = NettyChannelBuilder.forAddress("localhost", grpcServer_1WaySSL.port())
                .negotiationType(NegotiationType.TLS)
                .sslContext(sslContext)
                .build();

        // call the gRPC Echo service suggestion
        Echo.EchoResponse response = EchoServiceGrpc.newBlockingStub(channel).echo(Echo.EchoRequest.newBuilder().setMessage("foo").build());
        assertThat(response.getMessage(), is("foo"));

        ((ManagedChannel) channel).shutdown().awaitTermination(5, TimeUnit.SECONDS);
    }

    @Test
    public void shouldNotConnectWithoutCAFor1Way() throws Exception {
        // client do not have to provide certs for 1way ssl
        SslContext sslContext = clientSslContext(null, null, null);

        Channel channel = NettyChannelBuilder.forAddress("localhost", grpcServer_1WaySSL.port())
                .negotiationType(NegotiationType.TLS)
                .sslContext(sslContext)
                .build();

        // call the gRPC Echo service should throw
        Assertions.assertThrows(StatusRuntimeException.class,
                                ()->EchoServiceGrpc.newBlockingStub(channel).echo(Echo.EchoRequest.newBuilder().setMessage("foo").build()));

        ((ManagedChannel) channel).shutdown().awaitTermination(5, TimeUnit.SECONDS);
    }

    @Test
    public void shouldConnectWithClientCertsFor2Way() throws Exception {
        Resource tlsCaCert = Resource.create(CA_CERT);
        Resource tlsClientCert = Resource.create(CLIENT_CERT);
        Resource tlsClientKey = Resource.create(CLIENT_KEY);

        SslContext sslContext = clientSslContext(tlsCaCert, tlsClientCert, tlsClientKey);

        Channel channel = NettyChannelBuilder.forAddress("localhost", grpcServer_2WaySSL.port())
                    .negotiationType(NegotiationType.TLS)
                    .sslContext(sslContext)
                    .build();

        // call the gRPC Echo service
        Echo.EchoResponse response = EchoServiceGrpc.newBlockingStub(channel).echo(Echo.EchoRequest.newBuilder().setMessage("foo").build());
        assertThat(response.getMessage(), is("foo"));

        ((ManagedChannel) channel).shutdown().awaitTermination(5, TimeUnit.SECONDS);
    }

    @Test
    public void shouldNotConnectWithoutCAFor2Way() throws Exception {
        Resource tlsClientCert = Resource.create(CLIENT_CERT);
        Resource tlsClientKey = Resource.create(CLIENT_KEY);
        SslContext sslContext = clientSslContext(null, tlsClientCert, tlsClientKey);

        Channel channel = NettyChannelBuilder.forAddress("localhost", grpcServer_2WaySSL.port())
                .negotiationType(NegotiationType.TLS)
                .sslContext(sslContext)
                .build();

        // call the gRPC Echo service should throw
        Assertions.assertThrows(StatusRuntimeException.class,
                                ()->EchoServiceGrpc.newBlockingStub(channel).echo(Echo.EchoRequest.newBuilder().setMessage("foo").build()));

        ((ManagedChannel) channel).shutdown().awaitTermination(5, TimeUnit.SECONDS);
    }

    @Test
    public void shouldNotConnectWithoutClientCertFor2Way() throws Exception {
        Resource tlsCaCert = Resource.create(CA_CERT);
        Resource tlsClientKey = Resource.create(CLIENT_KEY);
        SslContext sslContext = clientSslContext(tlsCaCert, null, tlsClientKey);

        Channel channel = NettyChannelBuilder.forAddress("localhost", grpcServer_2WaySSL.port())
                .negotiationType(NegotiationType.TLS)
                .sslContext(sslContext)
                .build();

        // call the gRPC Echo service should throw
        Assertions.assertThrows(StatusRuntimeException.class,
                                ()->EchoServiceGrpc.newBlockingStub(channel).echo(Echo.EchoRequest.newBuilder().setMessage("foo").build()));

        ((ManagedChannel) channel).shutdown().awaitTermination(5, TimeUnit.SECONDS);
    }

    @Test
    public void shouldConnectWithClientCertsFor2WayUseConfig() throws Exception{
        Resource tlsCaCert = Resource.create(CA_CERT);
        Resource tlsClientCert = Resource.create(CLIENT_CERT);
        Resource tlsClientKey = Resource.create(CLIENT_KEY);
        SslContext sslContext = clientSslContext(tlsCaCert, tlsClientCert, tlsClientKey);

        Channel channel = NettyChannelBuilder.forAddress("localhost", grpcServer_2WaySSLConfig.port())
                .negotiationType(NegotiationType.TLS)
                .sslContext(sslContext)
                .build();

        // call the gRPC Echo service
        Echo.EchoResponse response = EchoServiceGrpc.newBlockingStub(channel).echo(Echo.EchoRequest.newBuilder().setMessage("foo").build());
        assertThat(response.getMessage(), is("foo"));

        ((ManagedChannel) channel).shutdown().awaitTermination(5, TimeUnit.SECONDS);
    }

    @Test
    public void shouldNotConnectWithoutClientCertFor2WayUseConfig() throws Exception {
        Resource tlsCaCert = Resource.create(CA_CERT);
        Resource tlsClientKey = Resource.create(CLIENT_KEY);
        SslContext sslContext = clientSslContext(tlsCaCert, null, tlsClientKey);

        Channel channel = NettyChannelBuilder.forAddress("localhost", grpcServer_2WaySSLConfig.port())
                .negotiationType(NegotiationType.TLS)
                .sslContext(sslContext)
                .build();

        // call the gRPC Echo service should throw
        Assertions.assertThrows(StatusRuntimeException.class,
                                ()->EchoServiceGrpc.newBlockingStub(channel).echo(Echo.EchoRequest.newBuilder().setMessage("foo").build()));

        ((ManagedChannel) channel).shutdown().awaitTermination(5, TimeUnit.SECONDS);
    }

    // ----- helper methods -------------------------------------------------

    private static SslContext clientSslContext(Resource trustCertCollectionFilePath,
                                               Resource clientCertChainFilePath,
                                               Resource clientPrivateKeyFilePath) throws SSLException {
        SslContextBuilder builder = GrpcSslContexts.forClient();
        if (trustCertCollectionFilePath != null) {
            builder.trustManager(trustCertCollectionFilePath.stream());
        }

        if (clientCertChainFilePath != null && clientPrivateKeyFilePath != null) {
            builder.keyManager(clientCertChainFilePath.stream(), clientPrivateKeyFilePath.stream());
        }
        return builder.build();
    }

    /**
     * Start the gRPC Server listening on the specified nPort.
     *
     * @throws Exception in case of an error
     */
    private static GrpcServer startGrpcServer(int nPort, boolean mutual, boolean useConfig ) throws Exception {
        Resource tlsCert = Resource.create(SERVER_CERT);
        Resource tlsKey = Resource.create(SERVER_KEY);
        Resource tlsCaCert = Resource.create(CA_CERT);

        GrpcTlsDescriptor sslConfig;
        String name = "grpc.server";
        if (useConfig) {
            name = name + 1;
            Config config = Config.builder().sources(ConfigSources.classpath("config-ssl.conf")).build();
            sslConfig = config.get("grpcserver.ssl").as(GrpcTlsDescriptor::create).get();
        } else if (mutual) {
            name = name + 2;
             sslConfig = GrpcTlsDescriptor.builder()
                        .jdkSSL(false)
                        .tlsCert(tlsCert)
                        .tlsKey(tlsKey)
                        .tlsCaCert(tlsCaCert)
                        .build();
        } else {
            name = name + 3;
            sslConfig = GrpcTlsDescriptor.builder()
                        .jdkSSL(false)
                        .tlsCert(tlsCert)
                        .tlsKey(tlsKey)
                        .build();
        }
        // Add the EchoService
        GrpcRouting routing = GrpcRouting.builder()
                                         .register(new EchoService())
                                         .build();

        GrpcServerConfiguration serverConfig = GrpcServerConfiguration.builder().name(name).port(nPort).tlsConfig(sslConfig).build();

        GrpcServer grpcServer ;
        try {
            grpcServer = GrpcServer.create(serverConfig, routing)
                    .start()
                    .toCompletableFuture()
                    .get(10, TimeUnit.SECONDS);
        } catch (Throwable t) {
            throw new RuntimeException(t);
        }

       LOGGER.info("Started gRPC server at: localhost:" + grpcServer.port());

       return grpcServer;
    }
}
