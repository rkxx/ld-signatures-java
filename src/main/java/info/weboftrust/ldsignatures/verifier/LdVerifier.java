package info.weboftrust.ldsignatures.verifier;

import com.danubetech.keyformats.crypto.ByteVerifier;
import foundation.identity.jsonld.JsonLDException;
import foundation.identity.jsonld.JsonLDObject;
import foundation.identity.jsonld.JsonLDUtils;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.canonicalizer.Canonicalizer;
import info.weboftrust.ldsignatures.jsonld.LDSecurityKeywords;
import info.weboftrust.ldsignatures.suites.SignatureSuite;
import info.weboftrust.ldsignatures.util.SHAUtil;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.stream.Collectors;

public abstract class LdVerifier<SIGNATURESUITE extends SignatureSuite> {

    private final SIGNATURESUITE signatureSuite;

    private ByteVerifier verifier;
    private Canonicalizer canonicalizer;

    private String proofPurpose;

    protected LdVerifier(SIGNATURESUITE signatureSuite, ByteVerifier verifier, Canonicalizer canonicalizer) {

        this.signatureSuite = signatureSuite;
        this.verifier = verifier;
        this.canonicalizer = canonicalizer;
    }

    /**
     * @deprecated Use LdVerifierRegistry.getLdVerifierBySignatureSuiteTerm(signatureSuiteTerm) instead.
     */
    @Deprecated
    public static LdVerifier<? extends SignatureSuite> ldVerifierForSignatureSuite(String signatureSuiteTerm) {
        return LdVerifierRegistry.getLdVerifierBySignatureSuiteTerm(signatureSuiteTerm);
    }

    /**
     * @deprecated Use LdVerifierRegistry.getLdVerifierBySignatureSuite(signatureSuite) instead.
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
            List<byte[]> digestedStatements = canonicalizationResult.stream().map(String::getBytes).collect(Collectors.toList());
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

    public boolean verifyProof(JsonLDObject jsonLDObject) throws IOException, GeneralSecurityException, JsonLDException {
        // get input proof
        LdProof ldProof = LdProof.getFromJsonLDObject(jsonLDObject);
        if (ldProof == null) return false;

        String proofPurpose = ldProof.getProofPurpose();
        if (proofPurpose==null || !proofPurpose.equals(this.proofPurpose)){
            throw new GeneralSecurityException("wrong proof purpose");
        }

        //prepare original proof
        LdProof originalLdProof = LdProof.fromJson(ldProof.toJson());
        // remove nonce
        JsonLDUtils.jsonLdRemove(originalLdProof, LDSecurityKeywords.JSONLD_TERM_NONCE);
        // set original proof type: BbsBlsSignatureProof2020 -> BbsBlsSignature2020
        JsonLDUtils.jsonLdRemove(originalLdProof, "type");
        JsonLDUtils.jsonLdAdd(originalLdProof,"type", "BbsBlsSignature2020");
        //
        List<String> canonicalizationResult = this.getCanonicalizer().canonicalize(originalLdProof, jsonLDObject);

        // transform uri blank node identifier (urn:bnid) back into internal blank node identifiers and return as byte[]
        List<byte[]> revealedMessages = canonicalizationResult.stream().map(statement -> statement.replaceAll("<urn:bnid:(_:c14n[0-9]*)>", "$1").getBytes()).collect(Collectors.toList());

        return ((BbsLdVerifier<?>)this).verifyProof(revealedMessages, ldProof);

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


    public String getProofPurpose() {
        return proofPurpose;
    }

    public void setProofPurpose(String proofPurpose) {
        this.proofPurpose = proofPurpose;
    }

}
