package org.nooplinux.certcheck;

import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
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

import javax.security.auth.x500.X500Principal;
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
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class CertificateValidator {

    static {
        Security.addProvider( new BouncyCastleProvider() );
    }

    private X509Certificate           x509Certificate;
    private Map<String, List<String>> subjectPrincipal;
    private Map<String, List<String>> issuerPrincipal;

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

            subjectPrincipal = getPrincipal( x509Certificate.getSubjectX500Principal() );
            issuerPrincipal = getPrincipal( x509Certificate.getIssuerX500Principal() );

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

    private Map<String, List<String>> getPrincipal( X500Principal x500Principal ) {
        Map<String, List<String>> principal = new HashMap<>();
        X500Name                  x500Name  = new X500Name( x500Principal.getName( "RFC1779" ) );
        for( RDN rdn : x500Name.getRDNs() ) {

            String name  = x500Name.getDefaultStyle().oidToDisplayName( rdn.getFirst().getType() );
            String value = rdn.getFirst().getValue().toString();

            List<String> values = principal.get( name );
            if( values == null ) {
                values = new ArrayList<>();
            }

            values.add( value );

            principal.put( name, values );
        }
        return principal;
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

        if( !algorithmId.equalsIgnoreCase( x509Certificate.getSigAlgName() ) ) {
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

    public CertificateValidator hasSubjectEmail( List<String> k ) {
        if( !subjectPrincipal.get( "E" ).contains( k ) ) {
            throw new CertificateValidatorException( "Subject Email " + subjectPrincipal.get( "E" ) + " does not contain " + k );

        }
        return this;
    }

    public CertificateValidator hasSubjectCommonName( List<String> k ) {
        if( !subjectPrincipal.get( "CN" ).contains( k ) ) {
            throw new CertificateValidatorException( "Subject CommonName " + subjectPrincipal.get( "CN" ) + " does not contain " + k );

        }
        return this;
    }

    public CertificateValidator hasSubjectOrganizationalUnit( List<String> k ) {
        if( !subjectPrincipal.get( "OU" ).contains( k ) ) {
            throw new CertificateValidatorException( "Subject OrganizationalUnit " + subjectPrincipal.get( "OU" ) + " does not contain " + k );

        }
        return this;
    }

    public CertificateValidator hasSubjectOrganization( List<String> k ) {
        if( !subjectPrincipal.get( "O" ).contains( k ) ) {
            throw new CertificateValidatorException( "Subject Organization " + subjectPrincipal.get( "E" ) + " does not contain " + k );

        }
        return this;
    }

    //Locality, City
    public CertificateValidator hasSubjectLocality( List<String> k ) {
        if( !subjectPrincipal.get( "L" ).contains( k ) ) {
            throw new CertificateValidatorException( "Subject Locality " + subjectPrincipal.get( "L" ) + " does not contain " + k );

        }
        return this;
    }

    //State, County, Region
    public CertificateValidator hasSubjectState( List<String> k ) {
        if( !subjectPrincipal.get( "ST" ).contains( k ) ) {
            throw new CertificateValidatorException( "Subject State " + subjectPrincipal.get( "ST" ) + " does not contain " + k );

        }
        return this;
    }

    public CertificateValidator hasSubjectCountry( List<String> k ) {
        if( !subjectPrincipal.get( "C" ).contains( k ) ) {
            throw new CertificateValidatorException( "Subject Country " + subjectPrincipal.get( "C" ) + " does not contain " + k );

        }
        return this;
    }

    public CertificateValidator hasIssuerEmail( List<String> k ) {
        if( !issuerPrincipal.get( "E" ).contains( k ) ) {
            throw new CertificateValidatorException( "Issuer Email " + issuerPrincipal.get( "E" ) + " does not contain " + k );

        }
        return this;
    }

    public CertificateValidator hasIssuerCommonName( List<String> k ) {
        if( !issuerPrincipal.get( "CN" ).contains( k ) ) {
            throw new CertificateValidatorException( "Issuer CommonName " + issuerPrincipal.get( "CN" ) + " does not contain " + k );

        }
        return this;
    }

    public CertificateValidator hasIssuerOrganizationalUnit( List<String> k ) {
        if( !issuerPrincipal.get( "OU" ).contains( k ) ) {
            throw new CertificateValidatorException( "Issuer OrganizationalUnit " + issuerPrincipal.get( "OU" ) + " does not contain " + k );

        }
        return this;
    }

    public CertificateValidator hasIssuerOrganization( List<String> k ) {
        if( !issuerPrincipal.get( "O" ).contains( k ) ) {
            throw new CertificateValidatorException( "Issuer Organization " + issuerPrincipal.get( "E" ) + " does not contain " + k );

        }
        return this;
    }

    //Locality, City
    public CertificateValidator hasIssuerLocality( List<String> k ) {
        if( !issuerPrincipal.get( "L" ).contains( k ) ) {
            throw new CertificateValidatorException( "Issuer Locality " + issuerPrincipal.get( "L" ) + " does not contain " + k );

        }
        return this;
    }

    //State, County, Region
    public CertificateValidator hasIssuerState( List<String> k ) {
        if( !issuerPrincipal.get( "ST" ).contains( k ) ) {
            throw new CertificateValidatorException( "Issuer State " + issuerPrincipal.get( "ST" ) + " does not contain " + k );

        }
        return this;
    }

    public CertificateValidator hasIssuerCountry( List<String> k ) {
        if( !issuerPrincipal.get( "C" ).contains( k ) ) {
            throw new CertificateValidatorException( "Issuer Country " + issuerPrincipal.get( "C" ) + " does not contain " + k );

        }
        return this;
    }

    public CertificateValidator equalsSubjectEmail( String k ) {
        if( subjectPrincipal.get( "E" ).size() != 1 && !subjectPrincipal.get( "E" ).contains( k ) ) {
            throw new CertificateValidatorException( "Subject Email " + subjectPrincipal.get( "E" ) + " does not just contain " + k );

        }
        return this;
    }

    public CertificateValidator equalsSubjectCommonName( String k ) {
        if( subjectPrincipal.get( "CN" ).size() != 1 && !subjectPrincipal.get( "CN" ).contains( k ) ) {
            throw new CertificateValidatorException( "Subject CommonName " + subjectPrincipal.get( "CN" ) + " does not just contain " + k );

        }
        return this;
    }

    public CertificateValidator equalsSubjectOrganizationalUnit( String k ) {
        if( subjectPrincipal.get( "OU" ).size() != 1 && !subjectPrincipal.get( "OU" ).contains( k ) ) {
            throw new CertificateValidatorException( "Subject OrganizationalUnit " + subjectPrincipal.get( "OU" ) + " does not just contain " + k );

        }
        return this;
    }

    public CertificateValidator equalsSubjectOrganization( String k ) {
        if( subjectPrincipal.get( "O" ).size() != 1 && !subjectPrincipal.get( "O" ).contains( k ) ) {
            throw new CertificateValidatorException( "Subject Organization " + subjectPrincipal.get( "E" ) + " does not just contain " + k );

        }
        return this;
    }

    //Locality, City
    public CertificateValidator equalsSubjectLocality( String k ) {
        if( subjectPrincipal.get( "L" ).size() != 1 && !subjectPrincipal.get( "L" ).contains( k ) ) {
            throw new CertificateValidatorException( "Subject Locality " + subjectPrincipal.get( "L" ) + " does not just contain " + k );

        }
        return this;
    }

    //State, County, Region
    public CertificateValidator equalsSubjectState( String k ) {
        if( subjectPrincipal.get( "ST" ).size() != 1 && !subjectPrincipal.get( "ST" ).contains( k ) ) {
            throw new CertificateValidatorException( "Subject State " + subjectPrincipal.get( "ST" ) + " does not just contain " + k );

        }
        return this;
    }

    public CertificateValidator equalsSubjectCountry( String k ) {
        if( subjectPrincipal.get( "C" ).size() != 1 && !subjectPrincipal.get( "C" ).contains( k ) ) {
            throw new CertificateValidatorException( "Subject Country " + subjectPrincipal.get( "C" ) + " does not just contain " + k );

        }
        return this;
    }

    public CertificateValidator equalsIssuerEmail( String k ) {
        if( issuerPrincipal.get( "E" ).size() != 1 && issuerPrincipal.get( "E" ).contains( k ) ) {
            throw new CertificateValidatorException( "Issuer Email " + issuerPrincipal.get( "E" ) + " does not just contain " + k );

        }
        return this;
    }

    public CertificateValidator equalsIssuerCommonName( String k ) {
        if( issuerPrincipal.get( "CN" ).size() != 1 && issuerPrincipal.get( "CN" ).contains( k ) ) {
            throw new CertificateValidatorException( "Issuer CommonName " + issuerPrincipal.get( "CN" ) + " does not just contain " + k );

        }
        return this;
    }

    public CertificateValidator equalsIssuerOrganizationalUnit( String k ) {
        if( issuerPrincipal.get( "OU" ).size() != 1 && issuerPrincipal.get( "OU" ).contains( k ) ) {
            throw new CertificateValidatorException( "Issuer OrganizationalUnit " + issuerPrincipal.get( "OU" ) + " does not just contain " + k );

        }
        return this;
    }

    public CertificateValidator equalsIssuerOrganization( String k ) {
        if( issuerPrincipal.get( "O" ).size() != 1 && issuerPrincipal.get( "O" ).contains( k ) ) {
            throw new CertificateValidatorException( "Issuer Organization " + issuerPrincipal.get( "E" ) + " does not just contain " + k );

        }
        return this;
    }

    //Locality, City
    public CertificateValidator equalsIssuerLocality( String k ) {
        if( issuerPrincipal.get( "L" ).size() != 1 && issuerPrincipal.get( "L" ).contains( k ) ) {
            throw new CertificateValidatorException( "Issuer Locality " + issuerPrincipal.get( "L" ) + " does not just contain " + k );

        }
        return this;
    }

    //State, County, Region
    public CertificateValidator equalsIssuerState( String k ) {
        if( issuerPrincipal.get( "ST" ).size() != 1 && issuerPrincipal.get( "ST" ).contains( k ) ) {
            throw new CertificateValidatorException( "Issuer State " + issuerPrincipal.get( "ST" ) + " does not just contain " + k );

        }
        return this;
    }

    public CertificateValidator equalsIssuerCountry( String k ) {
        if( issuerPrincipal.get( "C" ).size() != 1 && issuerPrincipal.get( "C" ).contains( k ) ) {
            throw new CertificateValidatorException( "Issuer Country " + issuerPrincipal.get( "C" ) + " does not just contain " + k );

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