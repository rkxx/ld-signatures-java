package info.weboftrust.ldsignatures.signer;

import com.apicatalog.jsonld.lang.Keywords;
import com.danubetech.keyformats.crypto.ByteSigner;
import foundation.identity.jsonld.JsonLDException;
import foundation.identity.jsonld.JsonLDObject;
import foundation.identity.jsonld.JsonLDUtils;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.canonicalizer.Canonicalizer;
import info.weboftrust.ldsignatures.suites.SignatureSuite;
import info.weboftrust.ldsignatures.util.SHAUtil;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import static info.weboftrust.ldsignatures.jsonld.LDSecurityContexts.JSONLD_CONTEXT_W3ID_SECURITY_V2;

public abstract class LdSigner<SIGNATURESUITE extends SignatureSuite> {

    private final SIGNATURESUITE signatureSuite;

    private ByteSigner signer;
    private Canonicalizer canonicalizer;

    private URI creator;
    private Date created;
    private String domain;
    private String challenge;
    private String nonce;
    private String proofPurpose;
    private URI verificationMethod;

    protected LdSigner(SIGNATURESUITE signatureSuite, ByteSigner signer, Canonicalizer canonicalizer) {

        this.signatureSuite = signatureSuite;
        this.signer = signer;
        this.canonicalizer = canonicalizer;
    }

    protected LdSigner(SIGNATURESUITE signatureSuite, ByteSigner signer, Canonicalizer canonicalizer, URI creator, Date created, String domain, String challenge, String nonce, String proofPurpose, URI verificationMethod) {

        this.signatureSuite = signatureSuite;
        this.signer = signer;
        this.canonicalizer = canonicalizer;
        this.creator = creator;
        this.created = created;
        this.domain = domain;
        this.challenge = challenge;
        this.nonce = nonce;
        this.proofPurpose = proofPurpose;
        this.verificationMethod = verificationMethod;
    }

    /**
     * @deprecated Use LdSignerRegistry.getLdSignerBySignatureSuiteTerm(signatureSuiteTerm) instead.
     */
    @Deprecated
    public static LdSigner<? extends SignatureSuite> ldSignerForSignatureSuite(String signatureSuiteTerm) {
        return LdSignerRegistry.getLdSignerBySignatureSuiteTerm(signatureSuiteTerm);
    }

    /**
     * @deprecated Use LdSignerRegistry.getLdSignerBySignatureSuite(signatureSuite) instead.
     */
    @Deprecated
    public static LdSigner<? extends SignatureSuite> ldSignerForSignatureSuite(SignatureSuite signatureSuite) {
        return LdSignerRegistry.getLdSignerBySignatureSuite(signatureSuite);
    }

    public abstract void sign(LdProof.Builder ldProofBuilder, byte[] signingInput) throws GeneralSecurityException;

    public LdProof sign(JsonLDObject jsonLdObject, boolean addToJsonLdObject, boolean defaultContexts) throws IOException, GeneralSecurityException, JsonLDException {

        // build the base proof object

        LdProof ldProof = LdProof.builder()
                .defaultContexts(false)
                .defaultTypes(false)
                .type(this.getSignatureSuite().getTerm())
                .creator(this.getCreator())
                .created(this.getCreated())
                .domain(this.getDomain())
                .challenge(this.getChallenge())
                .nonce(this.getNonce())
                .proofPurpose(this.getProofPurpose())
                .verificationMethod(this.getVerificationMethod())
                .build();

        // obtain the canonicalized document

        List<String> canonicalizationResult = this.getCanonicalizer().canonicalize(ldProof, jsonLdObject);

        // sign

        LdProof.Builder ldProofBuilder = LdProof.builder()
                .base(ldProof)
                .defaultContexts(defaultContexts);

        if (this instanceof BbsLdSigner) { // multi message signer
            List<byte[]> statements = canonicalizationResult.stream().map(statement -> {
                return statement.getBytes();
//                // transforms blank node id's to to proper ones and get bytes
//                byte[] bytes = statement.replaceAll("_:c14n[0-9]*", "<urn:bind:$0>").getBytes();
//                // applies statement digest algorithm
//                // TODO: validate that statement digest algorithm requires Blake2b256, it just defines Blake2b without length
//                Blake2b.Blake2b256 blake = new Blake2b.Blake2b256();
//                return blake.digest(bytes);
            }).collect(Collectors.toList());
            ((BbsLdSigner<?>) this).sign(ldProofBuilder, statements);

        } else {
            // calculates hashes of the normalized documents and concatenates them to one ByteArray
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            canonicalizationResult.forEach(statement -> {
                try {
                    baos.write(SHAUtil.sha256(statement));
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            });
            this.sign(ldProofBuilder, baos.toByteArray());
        }

        ldProof = ldProofBuilder.build();

        // add proof to JSON-LD

        if (addToJsonLdObject) ldProof.addToJsonLDObject(jsonLdObject);
        loadMissingContext(jsonLdObject);

        // done

        return ldProof;
    }

    private void loadMissingContext(JsonLDObject jsonLDObject) {
        if (this.getSignatureSuite().getSupportedJsonLDContexts().stream().noneMatch(jsonLDObject.getContexts()::contains)) {
            URI missingJsonLDContext = this.signatureSuite.getDefaultSupportedJsonLDContext();
            if (missingJsonLDContext != null) {
                JsonLDUtils.jsonLdAddAsJsonArray(jsonLDObject, Keywords.CONTEXT, missingJsonLDContext);
            }
        }
    }

    public LdProof sign(JsonLDObject jsonLdObject) throws IOException, GeneralSecurityException, JsonLDException {
        return this.sign(jsonLdObject, true, false);
    }

    public SignatureSuite getSignatureSuite() {
        return this.signatureSuite;
    }

    /*
     * Getters and setters
     */

    public ByteSigner getSigner() {
        return this.signer;
    }

    public void setSigner(ByteSigner signer) {
        this.signer = signer;
    }

    public Canonicalizer getCanonicalizer() {
        return canonicalizer;
    }

    public void setCanonicalizer(Canonicalizer canonicalizer) {
        this.canonicalizer = canonicalizer;
    }

    public URI getCreator() {
        return creator;
    }

    public void setCreator(URI creator) {
        this.creator = creator;
    }

    public Date getCreated() {
        return created;
    }

    public void setCreated(Date created) {
        this.created = created;
    }

    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public String getChallenge() {
        return challenge;
    }

    public void setChallenge(String challenge) {
        this.challenge = challenge;
    }

    public String getNonce() {
        return nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    public String getProofPurpose() {
        return proofPurpose;
    }

    public void setProofPurpose(String proofPurpose) {
        this.proofPurpose = proofPurpose;
    }

    public URI getVerificationMethod() {
        return verificationMethod;
    }

    public void setVerificationMethod(URI verificationMethod) {
        this.verificationMethod = verificationMethod;
    }
}
