package farm.puddle.certcheck;

import farm.puddle.certcheck.enums.CertificateType;
import farm.puddle.certcheck.exception.CertificateValidatorException;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.PolicyInformation;
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
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.util.*;

public class CertificateValidator {

    private static final String CERTIFICATE_POLICY_OID = "2.5.29.32";
    private static final String CERTIFICATE_SUBJECT_KEY_IDENTIFIER_OID = "2.5.29.14";

    //See https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/e563cff8-1af6-4e6f-a655-7571ca482e71
    private static final String CERTIFICATE_NTDS_CA_SECURITY_EXT_OID = "1.3.6.1.4.1.311.25.2";
    private static final String CERTIFICATE_NTDS_OBJECTSID_OID = "1.3.6.1.4.1.311.25.2.1";

    private static final Map<DNField, String> DNFieldToKey = new HashMap<DNField, String>() {{
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
    private static final Map<KUField, Integer> KUFieldToKey = new HashMap<KUField, Integer>() {{
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

    private final List<Integer> checkedKUs = new ArrayList<>();
    private final List<String> checkedEKUs = new ArrayList<>();
    private X509Certificate x509Certificate;
    private Map<String, List<String>> subjectPrincipal;
    private Map<String, List<String>> issuerPrincipal;

    private CertificateValidator() {
    }

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

    //TODO - need pkcs12 from file.

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

    public CertificateValidator(String base64PKCS12, String password)
            throws CertificateValidatorException {
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
                    return ((DLTaggedObject) ((DLSequence) ((DLTaggedObject) asn1Primitive).getObject()).getObjectAt(1)).getObject().toString();
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

    public CertificateValidator isValidWithPublicKey(PublicKey publicKey)
            throws CertificateValidatorException {
        try {
            x509Certificate.verify(publicKey);
        } catch (NoSuchProviderException | CertificateException | NoSuchAlgorithmException | InvalidKeyException |
                 SignatureException e) {
            throw new CertificateValidatorException(e);
        }
        return this;
    }

    public CertificateValidator equalsAlgorithmId(String algorithmId)
            throws CertificateValidatorException {
        if (!algorithmId.equalsIgnoreCase(x509Certificate.getSigAlgName())) {
            throw new CertificateValidatorException(x509Certificate.getSigAlgName() + " does not match " + algorithmId);
        }
        return this;
    }

    public CertificateValidator equalsSerialNumber(BigInteger serialNumber)
            throws CertificateValidatorException {
        if (!x509Certificate.getSerialNumber().equals(serialNumber)) {
            throw new CertificateValidatorException(x509Certificate.getSerialNumber() + " does not match " + serialNumber);
        }
        return this;
    }

    public CertificateValidator isValidWithDate(Date date)
            throws CertificateValidatorException {
        try {
            x509Certificate.checkValidity(date);
        } catch (CertificateNotYetValidException | CertificateExpiredException e) {
            throw new CertificateValidatorException(date.toString() + " is not within certificates validity period.", e);
        }

        return this;
    }

    public CertificateValidator equalsSubjectDNField(DNField dnField, List<String> k)
            throws CertificateValidatorException {
        String key = DNFieldToKey.get(dnField);

        if (!subjectPrincipal.get(key).equals(k)) {
            throw new CertificateValidatorException(dnField.name() + " " + subjectPrincipal.get(key) + " does not equal " + k);
        }
        return this;
    }

    public CertificateValidator equalsSubjectDNField(DNField dnField, String k)
            throws CertificateValidatorException {
        String key = DNFieldToKey.get(dnField);

        List<String> sn = subjectPrincipal.get(key);
        if (sn == null || !(sn.size() == 1 && sn.contains(k))) {
            throw new CertificateValidatorException(dnField.name() + " " + subjectPrincipal.get(key) + " does not equal " + k);
        }
        return this;
    }

    public CertificateValidator hasSubjectDNField(DNField dnField, boolean wantExists)
            throws CertificateValidatorException {
        String key = DNFieldToKey.get(dnField);

        List<String> sn = subjectPrincipal.get(key);

        if (sn == null && wantExists) {
            throw new CertificateValidatorException(dnField.name() + " does not exist.");
        } else if (sn != null && !wantExists) {
            throw new CertificateValidatorException(dnField.name() + " does exist: " + sn);
        }

        return this;
    }

    public CertificateValidator equalsIssuerDNField(DNField dnField, List<String> k)
            throws CertificateValidatorException {
        String key = DNFieldToKey.get(dnField);

        if (!issuerPrincipal.get(key).equals(k)) {
            throw new CertificateValidatorException(dnField.name() + " " + issuerPrincipal.get(key) + " does not equal " + k);
        }
        return this;
    }

    public CertificateValidator equalsIssuerDNField(DNField dnField, String k)
            throws CertificateValidatorException {
        String key = DNFieldToKey.get(dnField);

        List<String> sn = issuerPrincipal.get(key);
        if (sn == null || !(sn.size() == 1 && sn.contains(k))) {
            throw new CertificateValidatorException(dnField.name() + " " + issuerPrincipal.get(key) + " does not equal " + k);
        }
        return this;
    }

    public CertificateValidator hasIssuerDNField(DNField dnField, boolean wantExists)
            throws CertificateValidatorException {
        String key = DNFieldToKey.get(dnField);

        List<String> sn = issuerPrincipal.get(key);

        if (sn == null && wantExists) {
            throw new CertificateValidatorException(dnField.name() + " does not exist.");
        } else if (sn != null && !wantExists) {
            throw new CertificateValidatorException(dnField.name() + " does exist: " + sn);
        }

        return this;
    }

    public CertificateValidator hasKU(KUField kuField)
            throws CertificateValidatorException {
        Integer key = KUFieldToKey.get(kuField);
        if (!x509Certificate.getKeyUsage()[key]) {
            throw new CertificateValidatorException("Key Usage: " + kuField.name() + " does not exist.");
        }
        checkedKUs.add(key);
        return this;

    }

    public CertificateValidator noMoreKUs()
            throws CertificateValidatorException {
        boolean[] KUs = x509Certificate.getKeyUsage();
        for (int i = 0; i < KUs.length; i++) {
            if (KUs[i] && !checkedKUs.contains(i)) {
                throw new CertificateValidatorException("KU " + i + " exists but has not been checked.");
            }
        }
        return this;
    }

    public CertificateValidator hasExtendedKeyUsage(String eku)
            throws CertificateValidatorException {
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

    public CertificateValidator noMoreEKUs()
            throws CertificateValidatorException {
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
    public CertificateValidator hasUPN(String upn)
            throws CertificateValidatorException {
        try {
            final Collection<List<?>> subjectAltNames = x509Certificate.getSubjectAlternativeNames();
            if( subjectAltNames == null ) {
                throw new CertificateValidatorException("Subject Alternative Names is null");
            }

            String certUPN = null;
            for (List<?> sanItem : subjectAltNames) {
                Integer index = (Integer) sanItem.get(0);
                if (index == 0) { //otherName is UPN
                    certUPN = getStringFromSanObject(sanItem.get(1));
                    break;
                }
            }

            if (!upn.equals(certUPN)) {
                throw new CertificateValidatorException("UPN " + upn + " does not match " + certUPN);
            }
        } catch (Exception e) {
            throw new CertificateValidatorException(e);
        }
        return this;
    }

    public CertificateValidator hasRFC822Name(String name)
            throws CertificateValidatorException {
        try {
            final Collection<List<?>> subjectAltNames = x509Certificate.getSubjectAlternativeNames();
            if( subjectAltNames == null ) {
                throw new CertificateValidatorException("Subject Alternative Names is null");
            }

            String certName = null;
            for (List<?> sanItem : subjectAltNames) {
                Integer index = (Integer) sanItem.get(0);
                if (index == 1) {
                    certName = getStringFromSanObject(sanItem.get(1));
                    break;
                }
            }

            if (!name.equals(certName)) {
                throw new CertificateValidatorException("RFC882Name " + name + " does not match " + certName);
            }
        } catch (Exception e) {
            throw new CertificateValidatorException(e);
        }
        return this;
    }

    public CertificateValidator hasSubjectKeyIdentifier(String s)
            throws CertificateValidatorException {

        byte[] extensionValue = x509Certificate.getExtensionValue(CERTIFICATE_SUBJECT_KEY_IDENTIFIER_OID);
        if (extensionValue == null) {
            throw new CertificateValidatorException("Subject Key Identifier does not exist.");
        }

        byte[] subjectOctets = DEROctetString.getInstance(extensionValue).getOctets();
        SubjectKeyIdentifier.getInstance(subjectOctets);
        byte[] keyIdentifierBytes = SubjectKeyIdentifier.getInstance(subjectOctets).getKeyIdentifier();
        String keyIdentifierString = Hex.toHexString(keyIdentifierBytes).toLowerCase();

        if (!s.toLowerCase().equals(keyIdentifierString)) {
            throw new CertificateValidatorException("Subject Key Identifier " + s + " does not exist. It is " + keyIdentifierString);
        }

        return this;
    }

    //Note: Positions start at 0.
    public CertificateValidator hasCertificatePolicy(int policyPosition, String policy)
            throws CertificateValidatorException {
        if (policy == null) {
            throw new CertificateValidatorException("policy is null");
        }

        String certPolicy;
        try {
            certPolicy = getCertificatePolicyId(policyPosition);
        } catch (IOException e) {
            throw new CertificateValidatorException(e);
        }

        if (certPolicy == null) {
            throw new CertificateValidatorException("Policy not found at position " + policyPosition);
        }

        if (!policy.equals(certPolicy)) {
            throw new CertificateValidatorException(policy + " does not match " + certPolicy);
        }
        return this;
    }

    public CertificateValidator hasCertificatePolicyQualifier(int policyPosition, List<Integer> location, String qualifier)
            throws CertificateValidatorException {
        if (qualifier == null) {
            throw new CertificateValidatorException("qualifier is null");
        }

        String certQualifier;
        try {
            certQualifier = getCertificatePolicyQualifierInfo(policyPosition, location);
        } catch (IOException e) {
            throw new CertificateValidatorException(e);
        }

        if (certQualifier == null) {
            throw new CertificateValidatorException(qualifier + " not found at "
                    + policyPosition + ": " + location.toString());
        }

        if (!certQualifier.equals(qualifier)) {
            throw new CertificateValidatorException(certQualifier + " is not equal to " + qualifier);
        }

        return this;
    }

    private String getCertificatePolicyId(int certificatePolicyPos)
            throws IOException {

        CertificatePolicies certificatePolicies = getCertificatePolicy(certificatePolicyPos);
        if (certificatePolicies == null) {
            return null;
        }

        if (certificatePolicies.getPolicyInformation().length == 0) {
            return null;
        }

        PolicyInformation[] policyInformation = certificatePolicies.getPolicyInformation();
        if (policyInformation == null) {
            return null;
        }

        //Note: ID always seems to be at position 0, I can't seem to add multiple either so...hardcode it for now.
        return policyInformation[0].getPolicyIdentifier().getId();
    }

    private String getCertificatePolicyQualifierInfo(int certificatePolicyPos, List<Integer> location)
            throws IOException {

        CertificatePolicies certificatePolicies = getCertificatePolicy(certificatePolicyPos);
        if (certificatePolicies == null) {
            return null;
        }

        PolicyInformation[] policyInformation = certificatePolicies.getPolicyInformation();
        if (policyInformation == null) {
            return null;
        }

        ASN1Sequence qualifiers = policyInformation[0].getPolicyQualifiers();
        DLSequence seq = (DLSequence) qualifiers.getObjectAt(location.get(0));
        for (Integer loc : location.subList(1, location.size() - 1)) {
            seq = ((DLSequence) seq.getObjectAt(loc));
        }

        Object ret = seq.getObjectAt(location.get(location.size() - 1));

        return ret.toString();
    }

    private CertificatePolicies getCertificatePolicy(int certificatePolicyPos)
            throws IOException {
        byte[] extPolicyBytes = this.x509Certificate.getExtensionValue(CERTIFICATE_POLICY_OID);
        if (extPolicyBytes == null) {
            return null;
        }

        DEROctetString oct = (DEROctetString) (new ASN1InputStream(new ByteArrayInputStream(extPolicyBytes)).readObject());
        ASN1Sequence seq = (ASN1Sequence) new ASN1InputStream(new ByteArrayInputStream(oct.getOctets())).readObject();

        if (seq.size() <= (certificatePolicyPos)) {
            return null;
        }

        return new CertificatePolicies(PolicyInformation.getInstance(seq.getObjectAt(certificatePolicyPos)));
    }

    //https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/e563cff8-1af6-4e6f-a655-7571ca482e71
    public CertificateValidator hasMsObjectSid(String sid) {
        if (sid == null) {
            throw new CertificateValidatorException("sid is null");
        }

        byte[] extensionValue = x509Certificate.getExtensionValue(CERTIFICATE_NTDS_CA_SECURITY_EXT_OID);
        if (extensionValue == null) {
            throw new CertificateValidatorException(CERTIFICATE_NTDS_CA_SECURITY_EXT_OID + " does not exist.");
        }

        DLTaggedObject dlTaggedObject;
        try {
            DEROctetString derOctetString = (DEROctetString) DEROctetString.fromByteArray(extensionValue);
            DLSequence dlSequence = (DLSequence) ASN1Sequence.fromByteArray(derOctetString.getOctets());
            dlTaggedObject = (DLTaggedObject) dlSequence.getObjectAt(0);
        } catch (Exception e) {
            throw new CertificateValidatorException("Invalid format", e);
        }

        DLSequence dlSequence1;
        try {
            dlSequence1 = (DLSequence) dlTaggedObject.getBaseObject();
            ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) dlSequence1.getObjectAt(0);

            if (!oid.getId().equals(CERTIFICATE_NTDS_OBJECTSID_OID)) {
                throw new CertificateValidatorException("OID_NTDS_OBJECTSID not found. Found: " + oid.getId());
            }
        } catch (Exception e) {
            throw new CertificateValidatorException("OID_NTDS_OBJECTSID not found", e);
        }

        try {
            DLTaggedObject sidObject = (DLTaggedObject) dlSequence1.getObjectAt(1);
            DEROctetString derOctetStringSid = (DEROctetString) sidObject.getBaseObject();
            String certSid = new String(derOctetStringSid.getOctets(), StandardCharsets.UTF_8);
            if (!sid.equals(certSid)) {
                throw new CertificateValidatorException(certSid + " does not match " + sid);
            }

        } catch (Exception e) {
            throw new CertificateValidatorException("Cannot read SID string.", e);
        }

        return this;
    }

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
}
