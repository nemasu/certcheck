package org.nooplinux.certcheck;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.*;
import java.security.cert.*;
import java.util.Date;

public class CertificateValidator {

    static {
        Security.addProvider( new BouncyCastleProvider() );
    }

    X509Certificate x509Certificate;

    private CertificateValidator() {
    }

    private CertificateValidator( File file ) throws CertificateValidatorException, CertificateException {

        try {
            FileReader fileReader = null;
            fileReader = new FileReader( file );
            PemReader reader    = new PemReader( fileReader );
            PemObject pemObject = null;
            while( ( pemObject = reader.readPemObject() ) != null && !"CERTIFICATE".equals( pemObject.getType() ) ) {
                ;
            }

            X509CertificateHolder x509CertificateHolder = new X509CertificateHolder( pemObject.getContent() );
            x509Certificate = new JcaX509CertificateConverter().setProvider( BouncyCastleProvider.PROVIDER_NAME ).getCertificate(
                    x509CertificateHolder );
        } catch( IOException e ) {
            throw new CertificateValidatorException( e );
        }
    }

    public static CertificateValidator withPem( File file ) throws CertificateValidatorException, CertificateException {
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

    public CertificateValidator isAlgorithmId( String algorithmId ) {

        if( !algorithmId.equals( x509Certificate.getSigAlgName() ) ) {
            throw new CertificateValidatorException( x509Certificate.getSigAlgName() + " does not match " + algorithmId );
        }
        return this;
    }

    public CertificateValidator isValidWithDate( Date date ) {

        try {
            x509Certificate.checkValidity( date );
        } catch( CertificateNotYetValidException | CertificateExpiredException e ) {
            throw new CertificateValidatorException( date.toString() + " is not within certificates validity period.", e );
        }

        return this;
    }

    public CertificateValidator hasExtendedKeyUsage( String eku ) {
        try {
            if( !x509Certificate.getExtendedKeyUsage().contains( eku ) ) {
                throw new CertificateValidatorException( "Extended Key Usage not found." );
            }
        } catch( CertificateParsingException | NullPointerException e ) {
            throw new CertificateValidatorException( e );
        }

        return this;
    }

    //TODO move this out
    class CertificateValidatorException extends RuntimeException {
        public CertificateValidatorException( Exception exception ) {
            super( exception );
        }

        public CertificateValidatorException( String msg, Throwable e ) {
            super( msg, e );
        }

        public CertificateValidatorException( String message ) {
            super( message );
        }
    }
}