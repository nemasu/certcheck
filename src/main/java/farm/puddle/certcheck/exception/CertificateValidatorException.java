package farm.puddle.certcheck.exception;

public class CertificateValidatorException extends RuntimeException {

    private static final long serialVersionUID = -4478110368747577503L;

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
