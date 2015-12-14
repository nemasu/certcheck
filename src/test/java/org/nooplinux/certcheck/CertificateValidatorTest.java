package org.nooplinux.certcheck;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.junit.Test;
import sun.security.x509.AlgorithmId;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class CertificateValidatorTest {
    @Test
    public void TestValidKeyAndCert() throws Exception {
        CertificateValidator.withPem( getTestPemFile() ).isValidWithPublicKey( getTestPublicKey() );
    }

    @Test( expected = CertificateValidator.CertificateValidatorException.class )
    public void TestInvalidKeyAndCert() throws Exception {
        CertificateValidator.withPem( getTestPemFile() ).isValidWithPublicKey( getInvalidTestPublicKey() );
    }

    @Test
    public void TestAlgoId() throws Exception {
        CertificateValidator.withPem( getTestPemFile() ).isAlgorithmId( AlgorithmId.get( "SHA1WithRSA" ) );
    }

    private PublicKey getInvalidTestPublicKey() throws URISyntaxException, IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        ClassLoader classLoader   = getClass().getClassLoader();
        URL         publicKeyURL  = classLoader.getResource( "test-certs/domain.tld.invalid.pub" );
        File        publicKeyFile = new File( publicKeyURL.toURI() );
        try( FileReader fileReader = new FileReader( publicKeyFile ) ) {
            PemReader          reader             = new PemReader( fileReader );
            PemObject          pemObject          = reader.readPemObject();
            byte[]             publicKeyData      = pemObject.getContent();
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec( publicKeyData );
            KeyFactory         keyFactory         = KeyFactory.getInstance( "RSA" );
            return keyFactory.generatePublic( x509EncodedKeySpec );
        }
    }

    private PublicKey getTestPublicKey() throws URISyntaxException, IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        ClassLoader classLoader   = getClass().getClassLoader();
        URL         publicKeyURL  = classLoader.getResource( "test-certs/domain.tld.pub" );
        File        publicKeyFile = new File( publicKeyURL.toURI() );
        try( FileReader fileReader = new FileReader( publicKeyFile ) ) {
            PemReader          reader             = new PemReader( fileReader );
            PemObject          pemObject          = reader.readPemObject();
            byte[]             publicKeyData      = pemObject.getContent();
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec( publicKeyData );
            KeyFactory         keyFactory         = KeyFactory.getInstance( "RSA" );
            return keyFactory.generatePublic( x509EncodedKeySpec );
        }
    }

    private File getTestPemFile() throws URISyntaxException {
        ClassLoader classLoader = getClass().getClassLoader();
        URL         pemFileURL  = classLoader.getResource( "test-certs/domain.tld.pem" );
        return new File( pemFileURL.toURI() );
    }
}
