package org.nooplinux.certcheck;

import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.nooplinux.certcheck.enums.CertificateType;
import org.nooplinux.certcheck.exception.CertificateValidatorException;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;

public class CertificateValidator {

    static {
        Security.addProvider( new BouncyCastleProvider() );
    }

    X509Certificate x509Certificate;

    private CertificateValidator() {
    }

    private CertificateValidator( File file )
            throws CertificateValidatorException,
                   CertificateException,
                   SignatureException,
                   CMSException,
                   NoSuchAlgorithmException {

        try {
            FileReader fileReader;
            fileReader = new FileReader( file );
            PemReader       reader          = new PemReader( fileReader );
            PemObject       pemObject;
            CertificateType certificateType = null;

            //TODO We're just reading the top one, maybe add a skip number or a matcher or something?
            while( ( pemObject = reader.readPemObject() ) != null ) {

                if( "CERTIFICATE".equals( pemObject.getType() ) ) {
                    certificateType = CertificateType.PEM;
                    break;
                }

                if( "PKCS7".equals( pemObject.getType() ) ) {
                    //Reopen file for PEMParser.
                    certificateType = CertificateType.PKCS7;
                    reader.close();
                    fileReader.close();
                    fileReader = new FileReader( file );
                    reader = new PemReader( fileReader );
                    break;
                }
            }

            if( certificateType == null ) {
                throw new CertificateValidatorException( "Invalid certificate file." );
            }

            X509CertificateHolder x509CertificateHolder;
            switch( certificateType ) {
                case PEM:
                    x509CertificateHolder = new X509CertificateHolder( pemObject.getContent() );
                    x509Certificate = new JcaX509CertificateConverter().setProvider( BouncyCastleProvider.PROVIDER_NAME ).getCertificate(
                            x509CertificateHolder );
                    break;
                case PKCS7:
                    PEMParser pemParser = new PEMParser( reader );

                    ContentInfo cmsContentInfo = (ContentInfo) pemParser.readObject();

                    CMSSignedData cmsSignedData = new CMSSignedData( cmsContentInfo.getEncoded() );
                    Store store = cmsSignedData.getCertificates();
                    Collection<X509CertificateHolder> x509CertificateHolderCollection = store.getMatches( null );

                    //TODO We're just reading the top one, maybe add a skip number or a matcher or something?
                    x509CertificateHolder = x509CertificateHolderCollection.iterator().next();
                    x509Certificate = new JcaX509CertificateConverter().setProvider( BouncyCastleProvider.PROVIDER_NAME ).getCertificate(
                            x509CertificateHolder );
                    break;
                default:
                    break;
            }

        } catch( IOException e ) {
            throw new CertificateValidatorException( e );
        }
    }


    public static CertificateValidator withPem( File file )
            throws CertificateValidatorException,
                   CertificateException,
                   SignatureException,
                   CMSException,
                   NoSuchAlgorithmException {
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
}