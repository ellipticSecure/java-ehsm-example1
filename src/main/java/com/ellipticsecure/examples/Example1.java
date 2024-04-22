/*
 * Copyright (c) 2018 ellipticSecure - https://ellipticsecure.com
 *
 * All rights reserved.
 *
 * You may only use this code under the terms of the ellipticSecure software license.
 *
 */
package com.ellipticsecure.examples;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Calendar;
import java.util.Date;

/**
 * Demonstrate the use of elliptic curve cryptography using the eHSM hardware security module.
 *
 * @author Kobus Grobler
 */
public class Example1
{
    private static final String configName = "src/main/resources/ehsm.cfg";

    private static void eccDemo(Provider p, KeyStore ks, String algo, String curve) throws Exception {
        System.out.println("Testing curve "+ curve);

        String alias = "example1_test";
        // Delete previous test entry.
        ks.deleteEntry(alias);

        // Generate an EC key pair
        // Notice the use of the provider to force generation on the eHSM instead of software.
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", p);
        ECGenParameterSpec kpgparams = new ECGenParameterSpec(curve);
        keyPairGenerator.initialize(kpgparams);
        System.out.println("Generating key pair.");
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // Create a selfsigned certificate to store with the public key. This is a java keystore requirement.
        // the certificate is signed using the eHSM
        System.out.println("Creating self signed certificate.");
        X509Certificate cert = generateCert(
                keyPair,
                1,
                "SHA256withECDSA",
                "CN=example, L=Town, C=ZZ",
                null);
        ks.setKeyEntry(alias, keyPair.getPrivate(), null, new X509Certificate[]{cert});

        // sign some data
        Signature sig = Signature.getInstance(algo, p);
        sig.initSign(keyPair.getPrivate());
        byte[] data = "test".getBytes();
        sig.update(data);
        byte[] s = sig.sign();
        System.out.println("Signed with hardware key.");

        // verify the signature
        sig.initVerify(keyPair.getPublic());
        sig.update(data);
        if (!sig.verify(s)) {
            throw new Exception("signature did not verify");
        }
        System.out.println("Verified with hardware key.");
    }

    private static X509Certificate generateCert(KeyPair pair, int days, String algorithm, String dn, String provider) throws Exception {
        X500Name issuerName = new X500Name(dn);

        BigInteger serial = BigInteger.valueOf(new SecureRandom().nextInt()).abs();
        Calendar calendar = Calendar.getInstance();
        Date startDate = new Date();
        calendar.setTime(startDate);
        calendar.add(Calendar.DAY_OF_YEAR, days);

        Date endDate = calendar.getTime();
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuerName, serial, startDate, endDate, issuerName, pair.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));

        KeyUsage usage = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.dataEncipherment | KeyUsage.cRLSign);
        builder.addExtension(Extension.keyUsage, false, usage);

        ASN1EncodableVector purposes = new ASN1EncodableVector();
        purposes.add(KeyPurposeId.id_kp_serverAuth);
        purposes.add(KeyPurposeId.id_kp_clientAuth);
        purposes.add(KeyPurposeId.anyExtendedKeyUsage);
        builder.addExtension(Extension.extendedKeyUsage, false, new DERSequence(purposes));
        ContentSigner contentSigner = new JcaContentSignerBuilder(algorithm).build(pair.getPrivate());

        JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
        if (provider != null)
            converter.setProvider(provider);
        X509Certificate cert = converter.getCertificate(builder.build(contentSigner));
        cert.checkValidity(new Date());
        cert.verify(pair.getPublic());
        return cert;
    }

    public static void main( String[] args ) throws Exception
    {
        if (args.length < 1) {
            System.out.println("usage: example1 <SU password>");
            System.out.println("\tPlease provide the user (SU) password as the first parameter");
            return;
        }

        // Create PKCS11 Provider
        Provider p = Security.getProvider("SunPKCS11");
        p = p.configure(configName);
        Security.addProvider(p); 

        // Login to the eHSM
        KeyStore ks = KeyStore.getInstance("PKCS11", p);
        ks.load(null,args[0].toCharArray());

        eccDemo(p,ks,"SHA256withECDSA","secp256r1");
        eccDemo(p,ks,"SHA256withECDSA","secp384r1");
    }
}
