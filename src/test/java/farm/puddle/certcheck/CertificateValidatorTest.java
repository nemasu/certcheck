package farm.puddle.certcheck;

import farm.puddle.certcheck.CertificateValidator.DNField;
import farm.puddle.certcheck.exception.CertificateValidatorException;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.junit.Test;

import java.io.*;
import java.math.BigInteger;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

public class CertificateValidatorTest {

    // PKCS12
    @Test
    public void TestPKCS12Base64() {
        // This is generated by using:
        // openssl pkcs12 -export -inkey domain.tld.key -in domain.tld.crt | base64
        String base64 = "MIIGiQIBAzCCBk8GCSqGSIb3DQEHAaCCBkAEggY8MIIGODCCAzcGCSqGSIb3DQEHBqCCAygwggMk"
                + "AgEAMIIDHQYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQYwDgQIAMEENfWuPR4CAggAgIIC8GDoWYtL"
                + "xdmZtXsaRBWQOK4PoiXLqH0P0k5k0sUUSxZPKMFxCtG+kj8lRQwIZ4NDZOaX1NQtYaodMv/x5JpH"
                + "by5/AbjLY3o0u1y41/1M3w7YOjKER8neydvNI08zJO8O5L61zWKpIzWrhyTYRrf+BsUUiepAHOVb"
                + "9gyRdYWzZy3i4JrFhmGZ5i/6cUipo/VpJNT0Abl+4nTxuqp82O6A28jaVVviYqnb3NX3mfyNhjvG"
                + "Y0pqz9T4f6NAY9Tu+6cZSrc/66sI53bV1leb4JKwbSY9mEFGONiRfTMXG0nEozny9uHUzS9C4A/a"
                + "vg4kbzjH0gyiPwe6hkwJj9zMMS58SPkDBFzmlZQSvOut6P+tO0LJEbcNP7eZfU46XgbqBUnEVhpp"
                + "aQ+T+Gqxa3b2VvWmLope7Fftf1exHAD7eprSJyJP71ZXUbd84CnhJX94eBrFtPzD99rkz1bALK3E"
                + "ANG6QsXXg0hst9kXN2hGsIT9J9LK7pfQoAXnxTjuVv5l1PS7QiJhspQ3SCeZS+zYCSKCqmCMx4uV"
                + "VuhsKRXkl/U8V5Fk4mti5WnLOXe5c0XzFNVy9xiAznUB/C+stnIbC+0DiyPNocfEzMVRQV1QPcfr"
                + "bJrkyysu2ulweEIYfA0nWLwhjuBbpq7iuOgg+WizDTXamVK65thp3NyhC1YBrvgH+mYvCO29dZ4H"
                + "fEwrHDkzZh7lSNFhFmxWb0GLMqU0Cl+arMJ1mP6tVbM2R5HgOH263t/XwwPRPe9D2JZ3aNb08qjx"
                + "8imNie8ABTZnKDKbkJTyYR5aUvdQ03xI4nd6GWPq/ZVyR+SYIvV5+hRHJGkhqw/Jkpz6RK1Bd8GH"
                + "dECHCrHP83603wXMP+YnkuwdYVHdfSijDJiz8Xl/C1wh/UNnotmkHwROSLFSbi0Ho3ttjt23ZWIH"
                + "hFhZZkE2nLMaU7sQq/9YgLvIdT5ENIN8ZdV+mRgBHAptMj0PPYYebYVSMaLNtgfG5BE02E4/TNJc"
                + "d0zkIg1UMIIC+QYJKoZIhvcNAQcBoIIC6gSCAuYwggLiMIIC3gYLKoZIhvcNAQwKAQKgggKmMIIC"
                + "ojAcBgoqhkiG9w0BDAEDMA4ECA7TYGB8d1QAAgIIAASCAoCUM4x8zqSL0+azZp0xtg3slmSjPqO3"
                + "HU2ynFweWSXScgSds2+Ip1yaJ3CoXViv7qo+fs3SU/BPF60BcTqLY1fiIjHngYyTHXAodjtdeakN"
                + "/krp60Usw/65s1H+dESryPZ8H59jO4XMv8ngKbMdVs2NBgfSVGZt5hwk6NHi7Gu3KioyxBAXQnWX"
                + "QYCO9rTbz3flScGeLHpr/YqSr1gESYssHtBb31uVU4o1SP6+L/Th3y6hvZ39bfZJzM6VEhSOWFkO"
                + "O7TCM5W2SYYdqGGkL15TYyq4+trcCHXx2bgS8Rm/0v6YjNKOS3sOe7yxbh+ezbu4a2xOZwOqHt2S"
                + "22jlvtZPXgag19wUiS/EK7YRyzxTB5qDSVKsuaZz7pDmLV8prkYNUG8h70poa8LwJllm+ikCGwrS"
                + "8IH9M7P7PFlxl+3c+02UuhpL6nzQzaqeH+iPgavQMzd2LhD8dmlPFQ0xNlI80gaCpK/aQ1jGBP1G"
                + "MX1pxpN09j9SAuoRuaTBD0p2OhmYO4mkXBAgUkBTuED1DZDOLWbaEFeLskILq7WFAP6JUB1MgTz2"
                + "jsbU4xOuji79z0hwGfwv1CanKWQHSzNNcikmQxfG3/1KwIiRSZY03FeccCOYAeyfUNa3+5CgrSME"
                + "rDUgPjiqxHNGecEL2/7bA8fDyQ4t52OIrfp1VdIkjukftvpBGWTsoPOr8pRt/Qg2sIAIC0Ihicqm"
                + "PAUFAXgMous86cQmFSkObmSxjADZ2b5HK0OC1A4dxCaJTJdJLw6qo19O7F5AK/oH3Krsp8JUq3sN"
                + "Cl5zNEBakl+Ed21zb3Q/PKgqqZGppwCVGwLZl1LSBeJCAibYtpVoLZ6cACU3FMM/MSUwIwYJKoZI"
                + "hvcNAQkVMRYEFGu1p7cS/53KAOn4Zf6Tk7jIQozYMDEwITAJBgUrDgMCGgUABBTOmAwf9i2THFzO"
                + "ieYWtNzmWvUUMAQIt/zcSl1UVckCAggA";
        new CertificateValidator(base64, "1234aoeu1234aoeu") // This was provided during openssl command above.
                .equalsAlgorithmId("sha1withrsa")
                .equalsSubjectDNField(CertificateValidator.DNField.Email, "admin@domain.tld")
                .equalsSubjectDNField(CertificateValidator.DNField.CommonName, "domain.tld")
                .equalsSubjectDNField(CertificateValidator.DNField.OrganizationalUnit, "DevSec")
                .equalsSubjectDNField(CertificateValidator.DNField.Organization, "TestCompany1")
                .equalsSubjectDNField(CertificateValidator.DNField.Locality, "Shibuya")
                .equalsSubjectDNField(CertificateValidator.DNField.State, "Tokyo")
                .equalsSubjectDNField(CertificateValidator.DNField.Country, "JP");
    }

    // PEM
    @Test
    public void TestValidKeyAndCert() throws Exception {
        new CertificateValidator(getTestPemFile()).isValidWithPublicKey(getTestPublicKey());
        new CertificateValidator(getTestPemString()).isValidWithPublicKey(getTestPublicKey());
    }

    @Test(expected = CertificateValidatorException.class)
    public void TestInvalidKeyAndCert() throws Exception {
        new CertificateValidator(getTestPemFile()).isValidWithPublicKey(getInvalidTestPublicKey());
        new CertificateValidator(getTestPemString()).isValidWithPublicKey(getInvalidTestPublicKey());
    }

    @Test
    public void TestAlgoId() throws Exception {
        new CertificateValidator(getTestPemFile()).equalsAlgorithmId("SHA1WITHRSA");
        new CertificateValidator(getTestPemString()).equalsAlgorithmId("SHA1WITHRSA");
    }

    @Test(expected = CertificateValidatorException.class)
    public void TestNotBefore() throws Exception {
        Calendar gregorianCalendar = GregorianCalendar.getInstance();
        gregorianCalendar.setTimeZone(TimeZone.getTimeZone("GMT"));
        gregorianCalendar.set(2015, Calendar.OCTOBER, 21, 5, 43, 23);
        Date date = gregorianCalendar.getTime();

        new CertificateValidator(getTestPemFile()).isValidWithDate(date);
        new CertificateValidator(getTestPemString()).isValidWithDate(date);
    }

    @Test(expected = CertificateValidatorException.class)
    public void TestNotAfter() throws Exception {
        Calendar gregorianCalendar = GregorianCalendar.getInstance();
        gregorianCalendar.setTimeZone(TimeZone.getTimeZone("GMT"));
        gregorianCalendar.set(2016, Calendar.OCTOBER, 20, 5, 43, 25);
        Date date = gregorianCalendar.getTime();

        new CertificateValidator(getTestPemFile()).isValidWithDate(date);
        new CertificateValidator(getTestPemString()).isValidWithDate(date);
    }

    @Test
    public void TestValidDate() throws Exception {
        Calendar gregorianCalendar = GregorianCalendar.getInstance();
        gregorianCalendar.setTimeZone(TimeZone.getTimeZone("GMT"));
        gregorianCalendar.set(2016, Calendar.JANUARY, 1, 0, 0, 0);
        Date date = gregorianCalendar.getTime();

        new CertificateValidator(getTestPemFile()).isValidWithDate(date);
        new CertificateValidator(getTestPemString()).isValidWithDate(date);
    }

    // PKCS 7
    @Test
    public void TestPKCS7ValidKeyAndCert() throws Exception {
        new CertificateValidator(getTestPKCS7File()).isValidWithPublicKey(getTestPublicKey());
    }

    @Test(expected = CertificateValidatorException.class)
    public void TestPKCS7InvalidKeyAndCert() throws Exception {
        new CertificateValidator(getTestPKCS7File()).isValidWithPublicKey(getInvalidTestPublicKey());
    }

    @Test
    public void TestPKCS7AlgoId() throws Exception {
        new CertificateValidator(getTestPKCS7File()).equalsAlgorithmId("SHA1WITHRSA");
    }

    @Test(expected = CertificateValidatorException.class)
    public void TestPKCS7NotBefore() throws Exception {
        Calendar gregorianCalendar = GregorianCalendar.getInstance();
        gregorianCalendar.setTimeZone(TimeZone.getTimeZone("GMT"));
        gregorianCalendar.set(2015, Calendar.OCTOBER, 21, 5, 43, 23);
        Date date = gregorianCalendar.getTime();

        new CertificateValidator(getTestPKCS7File()).isValidWithDate(date);
    }

    @Test(expected = CertificateValidatorException.class)
    public void TestPKCS7NotAfter() throws Exception {
        Calendar gregorianCalendar = GregorianCalendar.getInstance();
        gregorianCalendar.setTimeZone(TimeZone.getTimeZone("GMT"));
        gregorianCalendar.set(2016, Calendar.OCTOBER, 20, 5, 43, 25);
        Date date = gregorianCalendar.getTime();

        new CertificateValidator(getTestPKCS7File()).isValidWithDate(date);
    }

    @Test
    public void TestPKCS7ValidDate() throws Exception {
        Calendar gregorianCalendar = GregorianCalendar.getInstance();
        gregorianCalendar.setTimeZone(TimeZone.getTimeZone("GMT"));
        gregorianCalendar.set(2016, Calendar.JANUARY, 1, 0, 0, 0);
        Date date = gregorianCalendar.getTime();

        new CertificateValidator(getTestPKCS7File()).isValidWithDate(date);
    }

    @Test
    public void TestPEMSubjectPrincipal() throws Exception {
        new CertificateValidator(getTestPemFile())
                .equalsAlgorithmId("sha1withrsa")
                .hasSubjectDNField(CertificateValidator.DNField.Email, true)
                .equalsSubjectDNField(CertificateValidator.DNField.Email, "admin@domain.tld")
                .equalsSubjectDNField(CertificateValidator.DNField.CommonName, "domain.tld")
                .equalsSubjectDNField(CertificateValidator.DNField.OrganizationalUnit, "DevSec")
                .equalsSubjectDNField(CertificateValidator.DNField.Organization, "TestCompany1")
                .equalsSubjectDNField(CertificateValidator.DNField.Locality, "Shibuya")
                .equalsSubjectDNField(CertificateValidator.DNField.State, "Tokyo")
                .equalsSubjectDNField(CertificateValidator.DNField.Country, "JP")
                .hasSubjectDNField(CertificateValidator.DNField.Surname, false)
                .hasIssuerDNField(CertificateValidator.DNField.OrganizationIdentifier, false);

        new CertificateValidator(getTestPemString())
                .equalsAlgorithmId("sha1withrsa")
                .equalsSubjectDNField(CertificateValidator.DNField.Email, "admin@domain.tld")
                .equalsSubjectDNField(CertificateValidator.DNField.CommonName, "domain.tld")
                .equalsSubjectDNField(CertificateValidator.DNField.OrganizationalUnit, "DevSec")
                .equalsSubjectDNField(CertificateValidator.DNField.Organization, "TestCompany1")
                .equalsSubjectDNField(CertificateValidator.DNField.Locality, "Shibuya")
                .equalsSubjectDNField(CertificateValidator.DNField.State, "Tokyo")
                .equalsSubjectDNField(CertificateValidator.DNField.Country, "JP");
    }

    @Test
    public void TestPEMSubjectPrincipalExt() throws Exception {
        new CertificateValidator(getExtTestPemFile())
                .equalsAlgorithmId("sha256withrsa")
                .hasSubjectDNField(CertificateValidator.DNField.Email, true)
                .equalsSubjectDNField(CertificateValidator.DNField.Email, "admin@domain.tld")
                .equalsSubjectDNField(CertificateValidator.DNField.CommonName, "domain.tld")
                .equalsSubjectDNField(CertificateValidator.DNField.OrganizationalUnit, "DevSec")
                .equalsSubjectDNField(CertificateValidator.DNField.Organization, "TestCompany1")
                .equalsSubjectDNField(CertificateValidator.DNField.State, "CA")
                .equalsSubjectDNField(CertificateValidator.DNField.Country, "US");

        new CertificateValidator(getTestExtPemString())
                .equalsAlgorithmId("sha256withrsa")
                .hasSubjectDNField(CertificateValidator.DNField.Email, true)
                .equalsSubjectDNField(CertificateValidator.DNField.Email, "admin@domain.tld")
                .equalsSubjectDNField(CertificateValidator.DNField.CommonName, "domain.tld")
                .equalsSubjectDNField(CertificateValidator.DNField.OrganizationalUnit, "DevSec")
                .equalsSubjectDNField(CertificateValidator.DNField.Organization, "TestCompany1")
                .equalsSubjectDNField(CertificateValidator.DNField.State, "CA")
                .equalsSubjectDNField(CertificateValidator.DNField.Country, "US");
    }

    @Test
    public void TestPEMIssuerPrincipal() throws Exception {
        new CertificateValidator(getTestPemFile())
                .equalsAlgorithmId("sha1withrsa")
                .equalsIssuerDNField(CertificateValidator.DNField.Email, "admin@domain.tld")
                .equalsIssuerDNField(CertificateValidator.DNField.CommonName, "domain.tld")
                .equalsIssuerDNField(CertificateValidator.DNField.OrganizationalUnit, "DevSec")
                .equalsIssuerDNField(CertificateValidator.DNField.Organization, "TestCompany1")
                .equalsIssuerDNField(CertificateValidator.DNField.Locality, "Shibuya")
                .equalsIssuerDNField(CertificateValidator.DNField.State, "Tokyo")
                .equalsIssuerDNField(CertificateValidator.DNField.Country, "JP");
        new CertificateValidator(getTestPemString())
                .equalsAlgorithmId("sha1withrsa")
                .equalsIssuerDNField(CertificateValidator.DNField.Email, "admin@domain.tld")
                .equalsIssuerDNField(CertificateValidator.DNField.CommonName, "domain.tld")
                .equalsIssuerDNField(CertificateValidator.DNField.OrganizationalUnit, "DevSec")
                .equalsIssuerDNField(CertificateValidator.DNField.Organization, "TestCompany1")
                .equalsIssuerDNField(CertificateValidator.DNField.Locality, "Shibuya")
                .equalsIssuerDNField(CertificateValidator.DNField.State, "Tokyo")
                .equalsIssuerDNField(CertificateValidator.DNField.Country, "JP");
    }

    @Test
    public void TestPEMKU_EKU() throws Exception {
        new CertificateValidator(getExtTestPemFile())
                .hasKU(CertificateValidator.KUField.digitalSignature)
                .hasKU(CertificateValidator.KUField.keyEncipherment)
                .hasExtendedKeyUsage("1.3.6.1.5.5.7.3.1")
                .hasExtendedKeyUsage("1.3.6.1.5.5.7.3.2")
                .noMoreKUs()
                .noMoreEKUs();
        new CertificateValidator(getTestExtPemString())
                .hasKU(CertificateValidator.KUField.digitalSignature)
                .hasKU(CertificateValidator.KUField.keyEncipherment)
                .hasExtendedKeyUsage("1.3.6.1.5.5.7.3.1")
                .hasExtendedKeyUsage("1.3.6.1.5.5.7.3.2")
                .noMoreKUs()
                .noMoreEKUs();
    }

    @Test
    public void TestPEMUPN() throws Exception {
        new CertificateValidator(getExtTestPemFile())
                .hasUPN("admin@domain.tld")
                .hasRFC822Name("admin@domain.tld");
        new CertificateValidator(getTestExtPemString())
                .hasUPN("admin@domain.tld")
                .hasRFC822Name("admin@domain.tld");
    }

    @Test
    public void TestGivenName() throws Exception {
        new CertificateValidator(getExtTestPemFile())
                .equalsSubjectDNField(CertificateValidator.DNField.GivenName, "Firstnamebert");

        new CertificateValidator((getTestExtPemString()))
                .equalsSubjectDNField(CertificateValidator.DNField.GivenName, "Firstnamebert");
    }

    @Test
    public void TestSurName() throws Exception {
        new CertificateValidator(getExtTestPemFile())
                .equalsSubjectDNField(CertificateValidator.DNField.Surname, "Lastnameson");
        new CertificateValidator((getTestExtPemString()))
                .equalsSubjectDNField(CertificateValidator.DNField.Surname, "Lastnameson");
    }

    @Test
    public void TestSKID() throws Exception {
        new CertificateValidator(getExtTestPemFile())
                .hasSubjectKeyIdentifier("f56a0906633bc2f1fc92e70bf5d29537fe4aacfc");
        new CertificateValidator((getTestExtPemString()))
                .hasSubjectKeyIdentifier("f56a0906633bc2f1fc92e70bf5d29537fe4aacfc");
    }

    @Test
    public void TestSerialNumber() throws Exception {
        new CertificateValidator(getExtTestPemFile())
                .equalsSerialNumber(new BigInteger("57c8be5f6fa4dc3deeb776eb3188ae492712ce96", 16));
        new CertificateValidator(getTestExtPemString())
                .equalsSerialNumber(new BigInteger("57c8be5f6fa4dc3deeb776eb3188ae492712ce96", 16));

        new CertificateValidator(getTestPemFile())
                .equalsSerialNumber(new BigInteger("00aeb76a4c3d4631a0", 16));
    }

    @Test
    public void TestOrgID() throws Exception {
        new CertificateValidator(getExtTestPemFile())
                .equalsSubjectDNField(CertificateValidator.DNField.OrganizationIdentifier, "My Organization ID");
        new CertificateValidator(getTestExtPemString())
                .equalsSubjectDNField(CertificateValidator.DNField.OrganizationIdentifier, "My Organization ID");
    }

    @Test
    public void TestDNSerialNumber() throws Exception {
        new CertificateValidator(getExtTestPemFile())
                .equalsSubjectDNField(CertificateValidator.DNField.SerialNumber, "My Serial Number");
        new CertificateValidator(getTestExtPemString())
                .equalsSubjectDNField(CertificateValidator.DNField.SerialNumber, "My Serial Number");
    }

    @Test
    public void TestCertificatePolicy() throws Exception {
        new CertificateValidator(getExtTestPemFile())
                .hasCertificatePolicy(0, "1.2.3.4")
                .hasCertificatePolicy(1, "1.5.6.7.8")
                .hasCertificatePolicy(2, "1.3.5.8");
        new CertificateValidator(getTestExtPemString())
                .hasCertificatePolicy(0, "1.2.3.4")
                .hasCertificatePolicy(1, "1.5.6.7.8")
                .hasCertificatePolicy(2, "1.3.5.8");
    }

    @Test
    public void TestCertificatePolicyQualifier() throws Exception {
        List<Integer> location = new ArrayList<>();
        location.add(1);
        location.add(1);
        new CertificateValidator(getExtTestPemFile())
                .hasCertificatePolicyQualifier(2, location, "http://my.your.example.com/");
        new CertificateValidator(getTestExtPemString())
                .hasCertificatePolicyQualifier(2, location, "http://my.your.example.com/");

        location.clear();
        location.add(2);
        location.add(1);
        location.add(0);
        location.add(1);
        location.add(1);
        new CertificateValidator(getExtTestPemFile())
                .hasCertificatePolicyQualifier(2, location, "2");
        new CertificateValidator(getTestExtPemString())
                .hasCertificatePolicyQualifier(2, location, "2");

        location.clear();
        location.add(2);
        location.add(1);
        location.add(1);
        new CertificateValidator(getExtTestPemFile())
                .hasCertificatePolicyQualifier(2, location, "Explicit Text Here");
        new CertificateValidator(getTestExtPemString())
                .hasCertificatePolicyQualifier(2, location, "Explicit Text Here");

    }

    @Test
    public void hasMSObjectSid() throws Exception {
        new CertificateValidator(getExtTestPemFile())
                .hasMsObjectSid("S-1-5-21-1468012755-800561317-457473099-500");
        new CertificateValidator(getTestExtPemString())
                .hasMsObjectSid("S-1-5-21-1468012755-800561317-457473099-500");
    }

    @Test
    public void hasPseudonym() throws Exception {
        new CertificateValidator(getExtTestPemFile())
                .equalsSubjectDNField(DNField.Pseudonym, "MyPseudonym");
        new CertificateValidator(getTestExtPemString())
                .equalsSubjectDNField(DNField.Pseudonym, "MyPseudonym");
    }

    private PublicKey getInvalidTestPublicKey()
            throws URISyntaxException, IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        ClassLoader classLoader = getClass().getClassLoader();
        URL publicKeyURL = classLoader.getResource("test-certs/domain.tld.invalid.pub");
        if (publicKeyURL == null) {
            throw new RuntimeException("Cannot find test-certs/domain.tld.invalid.pub resource.");
        }
        File publicKeyFile = new File(publicKeyURL.toURI());
        try (FileReader fileReader = new FileReader(publicKeyFile)) {
            PemReader reader = new PemReader(fileReader);
            PemObject pemObject = reader.readPemObject();
            byte[] publicKeyData = pemObject.getContent();
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKeyData);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(x509EncodedKeySpec);
        }
    }

    private PublicKey getTestPublicKey()
            throws URISyntaxException, IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        ClassLoader classLoader = getClass().getClassLoader();
        URL publicKeyURL = classLoader.getResource("test-certs/domain.tld.pub");
        if (publicKeyURL == null) {
            throw new RuntimeException("Cannot find test-certs/domain.tld.pub resource.");
        }
        File publicKeyFile = new File(publicKeyURL.toURI());
        try (FileReader fileReader = new FileReader(publicKeyFile)) {
            PemReader reader = new PemReader(fileReader);
            PemObject pemObject = reader.readPemObject();
            byte[] publicKeyData = pemObject.getContent();
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKeyData);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(x509EncodedKeySpec);
        }
    }

    private String getTestPemString() throws IOException {
        ClassLoader classLoader = getClass().getClassLoader();
        InputStream inputStream = classLoader.getResourceAsStream("test-certs/domain.tld.pem");
        if (inputStream == null) {
            throw new RuntimeException("Cannot find test-certs/domain.tld.pem resource.");
        }

        StringBuilder resultStringBuilder = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(inputStream))) {
            String line;
            while ((line = br.readLine()) != null) {
                resultStringBuilder.append(line).append("\n");
            }
        }
        return resultStringBuilder.toString();
    }

    private File getTestPemFile() throws URISyntaxException {
        ClassLoader classLoader = getClass().getClassLoader();
        URL pemFileURL = classLoader.getResource("test-certs/domain.tld.pem");
        if (pemFileURL == null) {
            throw new RuntimeException("Cannot find test-certs/domain.tld.pem resource.");
        }
        return new File(pemFileURL.toURI());
    }

    private String getTestExtPemString() throws IOException {
        ClassLoader classLoader = getClass().getClassLoader();
        InputStream inputStream = classLoader.getResourceAsStream("test-certs/ext_domain.tld.pem");
        if (inputStream == null) {
            throw new RuntimeException("Cannot find test-certs/ext_domain.tld.pem resource.");
        }

        StringBuilder resultStringBuilder = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(inputStream))) {
            String line;
            while ((line = br.readLine()) != null) {
                resultStringBuilder.append(line).append("\n");
            }
        }
        return resultStringBuilder.toString();
    }

    private File getExtTestPemFile() throws URISyntaxException {
        ClassLoader classLoader = getClass().getClassLoader();
        URL pemFileURL = classLoader.getResource("test-certs/ext_domain.tld.pem");
        if (pemFileURL == null) {
            throw new RuntimeException("Cannot find test-certs/ext_domain.tld.pem resource.");
        }
        return new File(pemFileURL.toURI());
    }

    private File getTestPKCS7File() throws URISyntaxException {
        ClassLoader classLoader = getClass().getClassLoader();
        URL pemFileURL = classLoader.getResource("test-certs/domain.tld.p7b");
        if (pemFileURL == null) {
            throw new RuntimeException("Cannot find test-certs/domain.tld.p7b resource.");
        }
        return new File(pemFileURL.toURI());
    }
}
