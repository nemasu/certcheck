package farm.puddle.certcheck;

import farm.puddle.certcheck.enums.CertificateType;
import farm.puddle.certcheck.exception.CertificateValidatorException;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.util.*;

public class CertificateValidator {

    public enum DNField {
        Email,
        CommonName,
        OrganizationalUnit,
        Organization,
        Locality,
        State,
        Country,
        Surname,
        GivenName,
        OrganizationIdentifier,
        SerialNumber
    }


    public enum KUField {
        digitalSignature,
        nonRepudiation,
        keyEncipherment,
        dataEncipherment,
        keyAgreement,
        keyCertSign,
        cRLSign,
        encipherOnly,
        decipherOnly
    }

    private static final Map<DNField,String> DNFieldToKey = new HashMap<DNField, String>(){{
        put(DNField.Email, "E");
        put(DNField.CommonName, "CN");
        put(DNField.OrganizationalUnit, "OU");
        put(DNField.Organization, "O");
        put(DNField.Locality, "L");
        put(DNField.State, "ST");
        put(DNField.Country, "C");
        put(DNField.Surname, "SURNAME");
        put(DNField.GivenName, "GIVENNAME");
        put(DNField.OrganizationIdentifier, "organizationIdentifier");
        put(DNField.SerialNumber, "SERIALNUMBER");

    }};

    /*
        KeyUsage ::= BIT STRING {
               digitalSignature        (0),
               nonRepudiation          (1),
               keyEncipherment         (2),
               dataEncipherment        (3),
               keyAgreement            (4),
               keyCertSign             (5),
               cRLSign                 (6),
               encipherOnly            (7),
               decipherOnly            (8) }
     */
    private static final Map<KUField,Integer> KUFieldToKey = new HashMap<KUField, Integer>(){{
        put(KUField.digitalSignature, 0);
        put(KUField.nonRepudiation, 1);
        put(KUField.keyEncipherment, 2);
        put(KUField.dataEncipherment, 3);
        put(KUField.keyAgreement, 4);
        put(KUField.keyCertSign, 5);
        put(KUField.cRLSign, 6);
        put(KUField.encipherOnly, 7);
        put(KUField.decipherOnly, 8);

    }};

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private X509Certificate x509Certificate;
    private Map<String, List<String>> subjectPrincipal;
    private Map<String, List<String>> issuerPrincipal;
    private List<Integer> checkedKUs = new ArrayList<>();
    private List<String> checkedEKUs = new ArrayList<>();

    private CertificateValidator() {
    }

    //TODO - need pkcs12 from file.

    public CertificateValidator(X509Certificate x509Certificate) {
        this.x509Certificate = x509Certificate;
        subjectPrincipal = getPrincipal(x509Certificate.getSubjectX500Principal());
        issuerPrincipal = getPrincipal(x509Certificate.getIssuerX500Principal());
    }

    //TODO factor this out with pem from file ctor.
    public CertificateValidator(String pemString)
            throws CertificateValidatorException,
            CertificateException,
            CMSException {

        try {
            StringReader stringReader = new StringReader(pemString);
            PemReader reader = new PemReader(stringReader);
            PemObject pemObject;
            CertificateType certificateType = null;

            //TODO We're just reading the top one, maybe add a skip number or a matcher or something?
            while ((pemObject = reader.readPemObject()) != null) {

                if ("CERTIFICATE".equals(pemObject.getType())) {
                    certificateType = CertificateType.PEM;
                    break;
                }

                if ("PKCS7".equals(pemObject.getType())) {
                    //Reopen stream for PEMParser.
                    certificateType = CertificateType.PKCS7;
                    reader.close();
                    stringReader.close();
                    stringReader = new StringReader(pemString);
                    reader = new PemReader(stringReader);
                    break;
                }
            }

            if (certificateType == null) {
                throw new CertificateValidatorException("Invalid certificate file.");
            }

            X509CertificateHolder x509CertificateHolder;
            switch (certificateType) {
                case PEM:
                    x509CertificateHolder = new X509CertificateHolder(pemObject.getContent());
                    x509Certificate = new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(
                            x509CertificateHolder);
                    break;
                case PKCS7:
                    PEMParser pemParser = new PEMParser(reader);

                    ContentInfo cmsContentInfo = (ContentInfo) pemParser.readObject();

                    CMSSignedData cmsSignedData = new CMSSignedData(cmsContentInfo.getEncoded());
                    Store store = cmsSignedData.getCertificates();
                    Collection<X509CertificateHolder> x509CertificateHolderCollection = store.getMatches(null);

                    //TODO We're just reading the top one, maybe add a skip number or a matcher or something?
                    x509CertificateHolder = x509CertificateHolderCollection.iterator().next();
                    x509Certificate = new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(
                            x509CertificateHolder);
                    break;
                default:
                    break;
            }

            subjectPrincipal = getPrincipal(x509Certificate.getSubjectX500Principal());
            issuerPrincipal = getPrincipal(x509Certificate.getIssuerX500Principal());

        } catch (IOException e) {
            throw new CertificateValidatorException(e);
        }
    }

    public CertificateValidator(File pemFile)
            throws CertificateValidatorException,
            CertificateException,
            CMSException {

        try {
            FileReader fileReader = new FileReader(pemFile);
            PemReader reader = new PemReader(fileReader);
            PemObject pemObject;
            CertificateType certificateType = null;

            //TODO We're just reading the top one, maybe add a skip number or a matcher or something?
            while ((pemObject = reader.readPemObject()) != null) {

                if ("CERTIFICATE".equals(pemObject.getType())) {
                    certificateType = CertificateType.PEM;
                    break;
                }

                if ("PKCS7".equals(pemObject.getType())) {
                    //Reopen file for PEMParser.
                    certificateType = CertificateType.PKCS7;
                    reader.close();
                    fileReader.close();
                    fileReader = new FileReader(pemFile);
                    reader = new PemReader(fileReader);
                    break;
                }
            }

            if (certificateType == null) {
                throw new CertificateValidatorException("Invalid certificate file.");
            }

            X509CertificateHolder x509CertificateHolder;
            switch (certificateType) {
                case PEM:
                    x509CertificateHolder = new X509CertificateHolder(pemObject.getContent());
                    x509Certificate = new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(
                            x509CertificateHolder);
                    break;
                case PKCS7:
                    PEMParser pemParser = new PEMParser(reader);

                    ContentInfo cmsContentInfo = (ContentInfo) pemParser.readObject();

                    CMSSignedData cmsSignedData = new CMSSignedData(cmsContentInfo.getEncoded());
                    Store store = cmsSignedData.getCertificates();
                    Collection<X509CertificateHolder> x509CertificateHolderCollection = store.getMatches(null);

                    //TODO We're just reading the top one, maybe add a skip number or a matcher or something?
                    x509CertificateHolder = x509CertificateHolderCollection.iterator().next();
                    x509Certificate = new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(
                            x509CertificateHolder);
                    break;
                default:
                    break;
            }

            subjectPrincipal = getPrincipal(x509Certificate.getSubjectX500Principal());
            issuerPrincipal = getPrincipal(x509Certificate.getIssuerX500Principal());

        } catch (IOException e) {
            throw new CertificateValidatorException(e);
        }
    }

    public CertificateValidator(String base64PKCS12, String password) {
        byte[] decodedCert = java.util.Base64.getDecoder().decode(base64PKCS12);
        try {

            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            InputStream inputStream = new ByteArrayInputStream(decodedCert);
            keyStore.load(inputStream, password.toCharArray());
            //TODO We're just reading the top one, maybe add a skip number or a matcher or something?
            java.security.cert.Certificate certificate = keyStore.getCertificate("1");
            if (certificate instanceof X509Certificate) {
                x509Certificate = (X509Certificate) certificate;
            } else {
                throw new RuntimeException("Error in create from base64 pkcs12 - Invalid cert type");
            }

            subjectPrincipal = getPrincipal(x509Certificate.getSubjectX500Principal());
            issuerPrincipal = getPrincipal(x509Certificate.getIssuerX500Principal());
        } catch (Exception e) {
            throw new RuntimeException("Error in create from base64 pkcs12 - Invalid cert", e);
        }
    }

    private static String getStringFromSanObject(Object item) {
        try {
            ASN1InputStream decoder = null;
            if (item instanceof byte[]) {
                decoder = new ASN1InputStream((byte[]) item);
                ASN1Primitive asn1Primitive = decoder.readObject();

                DERTaggedObject derTaggedObject = null;
                //...this is ridiculous
                if (asn1Primitive instanceof DERTaggedObject) {
                    derTaggedObject = (DERTaggedObject) asn1Primitive;
                    return ((DERTaggedObject) ((DLSequence) derTaggedObject.getObject()).getObjectAt(1)).getObject()
                            .toString();
                } else if (asn1Primitive instanceof DLSequence) {
                    DLSequence dlSequence = (DLSequence) asn1Primitive;
                    derTaggedObject = (DERTaggedObject) dlSequence.getObjectAt(1);
                    return ((DERTaggedObject) derTaggedObject.getObject()).getObject().toString();
                } else if (asn1Primitive instanceof DLTaggedObject) {
                    return ((DLTaggedObject)((DLSequence)((DLTaggedObject) asn1Primitive).getObject()).getObjectAt(1)).getObject().toString();
                }
            } else if (item instanceof String) {
                return (String) item;
            }
        } catch (Exception e) {
            throw new CertificateValidatorException(e);
        }
        return null;
    }

    private Map<String, List<String>> getPrincipal(X500Principal x500Principal) {
        Map<String, List<String>> principal = new HashMap<>();
        X500Name x500Name = new X500Name(x500Principal.getName("RFC1779"));
        for (RDN rdn : x500Name.getRDNs()) {

            String name = X500Name.getDefaultStyle().oidToDisplayName(rdn.getFirst().getType());
            String value = rdn.getFirst().getValue().toString();

            List<String> values = principal.get(name);
            if (values == null) {
                values = new ArrayList<>();
            }

            values.add(value);

            principal.put(name, values);
        }
        return principal;
    }

    public CertificateValidator isValidWithPublicKey(PublicKey publicKey) throws CertificateValidatorException {
        try {
            x509Certificate.verify(publicKey);
        } catch (NoSuchProviderException | CertificateException | NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new CertificateValidatorException(e);
        }
        return this;
    }

    public CertificateValidator equalsAlgorithmId(String algorithmId) {

        if (!algorithmId.equalsIgnoreCase(x509Certificate.getSigAlgName())) {
            throw new CertificateValidatorException(x509Certificate.getSigAlgName() + " does not match " + algorithmId);
        }
        return this;
    }

    public CertificateValidator equalsSerialNumber( BigInteger serialNumber ) {
        if (!x509Certificate.getSerialNumber().equals( serialNumber )) {
            throw new CertificateValidatorException(x509Certificate.getSerialNumber() + " does not match " + serialNumber);
        }
        return this;
    }

    public CertificateValidator isValidWithDate(Date date) {

        try {
            x509Certificate.checkValidity(date);
        } catch (CertificateNotYetValidException | CertificateExpiredException e) {
            throw new CertificateValidatorException(date.toString() + " is not within certificates validity period.", e);
        }

        return this;
    }

    public CertificateValidator equalsSubjectDNField(DNField dnField, List<String> k) {
        String key = DNFieldToKey.get(dnField);

        if (!subjectPrincipal.get(key).equals(k)) {
            throw new CertificateValidatorException(dnField.name() + " " + subjectPrincipal.get(key) + " does not equal " + k);
        }
        return this;
    }

    public CertificateValidator equalsSubjectDNField(DNField dnField, String k) {
        String key = DNFieldToKey.get(dnField);

        List<String> sn = subjectPrincipal.get(key);
        if(sn == null || !(sn.size() == 1 && sn.contains(k))) {
            throw new CertificateValidatorException(dnField.name() + " " + subjectPrincipal.get(key) + " does not equal " + k);
        }
        return this;
    }

    public CertificateValidator hasSubjectDNField(DNField dnField, boolean wantExists) {
        String key = DNFieldToKey.get(dnField);

        List<String> sn = subjectPrincipal.get(key);

        if (sn == null && wantExists) {
            throw new CertificateValidatorException(dnField.name() + " does not exist.");
        } else if ( sn != null && !wantExists ) {
            throw new CertificateValidatorException(dnField.name() + " does exist: " + sn.toString());
        }

        return this;
    }

    public CertificateValidator equalsIssuerDNField(DNField dnField, List<String> k) {
        String key = DNFieldToKey.get( dnField );

        if (!issuerPrincipal.get(key).equals(k)) {
            throw new CertificateValidatorException(dnField.name() + " " + issuerPrincipal.get(key) + " does not equal " + k);
        }
        return this;
    }

    public CertificateValidator equalsIssuerDNField(DNField dnField, String k) {
        String key = DNFieldToKey.get( dnField );

        List<String> sn = issuerPrincipal.get( key );
        if(sn == null || !( sn.size() == 1 && sn.contains( k ) ) ) {
            throw new CertificateValidatorException(dnField.name() + " " + issuerPrincipal.get(key) + " does not equal " + k);
        }
        return this;
    }

    public CertificateValidator hasIssuerDNField(DNField dnField, boolean wantExists) {
        String key = DNFieldToKey.get(dnField);

        List<String> sn = issuerPrincipal.get(key);

        if ( sn == null && wantExists) {
            throw new CertificateValidatorException(dnField.name() + " does not exist.");
        } else if ( sn != null && !wantExists ) {
            throw new CertificateValidatorException(dnField.name() + " does exist: " + sn.toString());
        }

        return this;
    }

    public CertificateValidator hasKU(KUField kuField) {
        Integer key = KUFieldToKey.get( kuField );
        if (!x509Certificate.getKeyUsage()[key]) {
            throw new CertificateValidatorException("Key Usage: " + kuField.name() + " does not exist.");
        }
        checkedKUs.add(key);
        return this;

    }

    public CertificateValidator noMoreKUs() {
        boolean[] KUs = x509Certificate.getKeyUsage();
        for (int i = 0; i < KUs.length; i++) {
            if (KUs[i] && !checkedKUs.contains(i)) {
                throw new CertificateValidatorException("KU " + i + " exists but has not been checked.");
            }
        }
        return this;
    }

    public CertificateValidator hasExtendedKeyUsage(String eku) {
        try {
            if (!x509Certificate.getExtendedKeyUsage().contains(eku)) {
                throw new CertificateValidatorException("Extended Key Usage " + eku + "  not found.");
            }
        } catch (CertificateParsingException | NullPointerException e) {
            throw new CertificateValidatorException(e);
        }
        checkedEKUs.add(eku);
        return this;
    }

    public CertificateValidator noMoreEKUs() {
        try {
            for (final String EKU : x509Certificate.getExtendedKeyUsage()) {
                if (!checkedEKUs.contains(EKU)) {
                    throw new CertificateValidatorException("EKU " + EKU + " exists but has not been checked.");
                }
            }
        } catch (Exception e) {
            throw new CertificateValidatorException(e);
        }
        return this;
    }

    /*
        GeneralName ::= CHOICE {
            otherName                       [0]     OtherName,
            rfc822Name                      [1]     IA5String,
            dNSName                         [2]     IA5String,
            x400Address                     [3]     ORAddress,
            directoryName                   [4]     Name,
            ediPartyName                    [5]     EDIPartyName,
            uniformResourceIdentifier       [6]     IA5String,
            iPAddress                       [7]     OCTET STRING,
            registeredID                    [8]     OBJECT IDENTIFIER}
     */
    public CertificateValidator hasUPN(String upn) {
        try {
            final Collection<List<?>> subjectAltNames = x509Certificate.getSubjectAlternativeNames();

            String certUPN = null;
            for (List<?> sanItem : subjectAltNames) {
                Integer index = (Integer) sanItem.get(0);
                if (index == 0) { //otherName is UPN
                    certUPN = getStringFromSanObject(sanItem.get(1));
                    break;
                }
            }

            if (!upn.equals(certUPN)) {
                throw new CertificateValidatorException("UPN " + upn + " does not exist.");
            }
        } catch (Exception e) {
            throw new CertificateValidatorException(e);
        }
        return this;
    }

    public CertificateValidator hasRFC822Name(String name) {
        try {
            final Collection<List<?>> subjectAltNames = x509Certificate.getSubjectAlternativeNames();
            String certName = null;
            for (List<?> sanItem : subjectAltNames) {
                Integer index = (Integer) sanItem.get(0);
                if (index == 1) {
                    certName = getStringFromSanObject(sanItem.get(1));
                    break;
                }
            }

            if (!name.equals(certName)) {
                throw new CertificateValidatorException("RFC882Name " + name + " does not exist.");
            }
        } catch (Exception e) {
            throw new CertificateValidatorException(e);
        }
        return this;
    }

    public CertificateValidator hasSubjectKeyIdentifier(String s) {

        byte[] extensionValue = x509Certificate.getExtensionValue("2.5.29.14");
        byte[] subjectOctets = DEROctetString.getInstance(extensionValue).getOctets();
        SubjectKeyIdentifier.getInstance(subjectOctets);
        byte[] keyIdentifierBytes = SubjectKeyIdentifier.getInstance(subjectOctets).getKeyIdentifier();
        String keyIdentifierString = Hex.toHexString(keyIdentifierBytes).toLowerCase();

        if( !s.toLowerCase().equals(keyIdentifierString)) {
            throw new CertificateValidatorException("Subject Key Identifier " + s + " does not exist. It is " + keyIdentifierString);
        }

        return this;
    }
}
