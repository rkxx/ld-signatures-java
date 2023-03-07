package info.weboftrust.ldsignatures.verifier;

import com.danubetech.keyformats.crypto.ByteVerifier;
import foundation.identity.jsonld.JsonLDException;
import foundation.identity.jsonld.JsonLDObject;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.canonicalizer.Canonicalizer;
import info.weboftrust.ldsignatures.suites.SignatureSuite;
import info.weboftrust.ldsignatures.util.SHAUtil;
import org.bouncycastle.jcajce.provider.digest.Blake2b;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.stream.Collectors;

public abstract class LdVerifier<SIGNATURESUITE extends SignatureSuite> {

    private final SIGNATURESUITE signatureSuite;

    private ByteVerifier verifier;
    private Canonicalizer canonicalizer;

    protected LdVerifier(SIGNATURESUITE signatureSuite, ByteVerifier verifier, Canonicalizer canonicalizer) {

        this.signatureSuite = signatureSuite;
        this.verifier = verifier;
        this.canonicalizer = canonicalizer;
    }

    /**
     * @deprecated
     * Use LdVerifierRegistry.getLdVerifierBySignatureSuiteTerm(signatureSuiteTerm) instead.
     */
    @Deprecated
    public static LdVerifier<? extends SignatureSuite> ldVerifierForSignatureSuite(String signatureSuiteTerm) {
        return LdVerifierRegistry.getLdVerifierBySignatureSuiteTerm(signatureSuiteTerm);
    }

    /**
     * @deprecated
     * Use LdVerifierRegistry.getLdVerifierBySignatureSuite(signatureSuite) instead.
     */
    @Deprecated
    public static LdVerifier<? extends SignatureSuite> ldVerifierForSignatureSuite(SignatureSuite signatureSuite) {
        return LdVerifierRegistry.getLdVerifierBySignatureSuite(signatureSuite);
    }

    public abstract boolean verify(byte[] signingInput, LdProof ldProof) throws GeneralSecurityException;

    public boolean verify(JsonLDObject jsonLdObject, LdProof ldProof) throws IOException, GeneralSecurityException, JsonLDException {

        // check the proof object

        if (!this.getSignatureSuite().getTerm().equals(ldProof.getType()))
            throw new GeneralSecurityException("Unexpected signature type: " + ldProof.getType() + " is not " + this.getSignatureSuite().getTerm());

        // obtain the canonicalized document

        List<String> canonicalizationResult = this.getCanonicalizer().canonicalize(ldProof, jsonLdObject);

        // verify

        if (this instanceof BbsLdVerifier) { // multi message verifier
            List<byte[]> digestedStatements = canonicalizationResult.stream().map(statement -> {
                return statement.getBytes() ;
//                // transforms blank node id's to to proper ones and get bytes
//                byte[] bytes = statement.replaceAll("_:c14n[0-9]*", "<urn:bind:$0>").getBytes();
//                // applies statement digest algorithm
//                // TODO: validate that statement digest algorithm requires Blake2b256, https://w3c-ccg.github.io/ldp-bbs2020/#the-bbs-signature-proof-suite-2020 just defines Blake2b without length
//                Blake2b.Blake2b256 blake = new Blake2b.Blake2b256();
//                return blake.digest(bytes);
            }).collect(Collectors.toList());
            return ((BbsLdVerifier<?>) this).verify(digestedStatements, ldProof);
        } else {
            // calculates hashes of the normalized documents and concatenates them to one ByteArray
           ByteArrayOutputStream baos = new ByteArrayOutputStream();
            canonicalizationResult.forEach(document -> {
                try {
                    baos.write(SHAUtil.sha256(document));
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            });
            return verify(baos.toByteArray(), ldProof);
        }
   }

    public boolean verify(JsonLDObject jsonLdObject) throws IOException, GeneralSecurityException, JsonLDException {

        // obtain the signature object

        LdProof ldProof = LdProof.getFromJsonLDObject(jsonLdObject);
        if (ldProof == null) return false;

        // done

        return this.verify(jsonLdObject, ldProof);
    }

    public SignatureSuite getSignatureSuite() {
        return this.signatureSuite;
    }

    /*
     * Getters and setters
     */

    public ByteVerifier getVerifier() {
        return this.verifier;
    }

    public void setVerifier(ByteVerifier verifier) {
        this.verifier = verifier;
    }

    public Canonicalizer getCanonicalizer() {
        return canonicalizer;
    }

    public void setCanonicalizer(Canonicalizer canonicalizer) {
        this.canonicalizer = canonicalizer;
    }
}
