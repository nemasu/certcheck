package org.nooplinux.certcheck;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import sun.security.x509.AlgorithmId;

import javax.security.cert.CertificateException;
import javax.security.cert.X509Certificate;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.*;

public class CertificateValidator {

    X509Certificate x509Certificate;

    private CertificateValidator() {
    }

    private CertificateValidator( File file ) throws CertificateValidatorException {

        try {
            FileReader fileReader = null;
            fileReader = new FileReader( file );
            PemReader reader    = new PemReader( fileReader );
            PemObject pemObject = null;
            while( ( pemObject = reader.readPemObject() ) != null && !"CERTIFICATE".equals( pemObject.getType() ) ) {
                ;
            }

            this.x509Certificate = X509Certificate.getInstance( pemObject.getContent() );
        } catch( CertificateException | IOException e ) {
            throw new CertificateValidatorException( e );
        }
    }

    public static CertificateValidator withPem( File file ) throws CertificateValidatorException {
        return new CertificateValidator( file );
    }

    public CertificateValidator isValidWithPublicKey( PublicKey publicKey ) throws CertificateValidatorException {
        try {
            x509Certificate.verify( publicKey );
        } catch( NoSuchProviderException | CertificateException | NoSuchAlgorithmException | InvalidKeyException | SignatureException e ) {
            throw new CertificateValidatorException( e );
        }
        return this;
    }

    public CertificateValidator isAlgorithmId( AlgorithmId algorithmId ) {

        if( !algorithmId.getName().equals( x509Certificate.getSigAlgName() ) ) {
            throw new CertificateValidatorException( x509Certificate.getSigAlgName() + " does not match " + algorithmId );
        }
        return this;
    }

    //TODO move this out
    class CertificateValidatorException extends RuntimeException {
        public CertificateValidatorException( Exception exception ) {
            super( exception );
        }

        public CertificateValidatorException( String message ) {
            super( message );
        }
    }
}