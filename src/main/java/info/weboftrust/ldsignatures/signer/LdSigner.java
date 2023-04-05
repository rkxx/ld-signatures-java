package info.weboftrust.ldsignatures.signer;

import bbs.signatures.ProofMessage;
import com.apicatalog.jsonld.JsonLd;
import com.apicatalog.jsonld.JsonLdError;
import com.apicatalog.jsonld.document.JsonDocument;
import com.apicatalog.jsonld.document.RdfDocument;
import com.apicatalog.jsonld.http.media.MediaType;
import com.apicatalog.jsonld.lang.Keywords;
import com.danubetech.keyformats.crypto.ByteSigner;
import com.danubetech.keyformats.crypto.provider.RandomProvider;
import foundation.identity.jsonld.JsonLDException;
import foundation.identity.jsonld.JsonLDObject;
import foundation.identity.jsonld.JsonLDUtils;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.canonicalizer.Canonicalizer;
import info.weboftrust.ldsignatures.suites.BbsBlsSignatureProof2020SignatureSuite;
import info.weboftrust.ldsignatures.suites.SignatureSuite;
import info.weboftrust.ldsignatures.util.SHAUtil;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.util.*;
import java.util.stream.Collectors;

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
            List<byte[]> statements = canonicalizationResult.stream().map(String::getBytes).collect(Collectors.toList());
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
                JsonLDUtils.jsonLdAddAsJsonArray(jsonLDObject, Keywords.CONTEXT, missingJsonLDContext.toString());
            }
        }
    }

    public LdProof sign(JsonLDObject jsonLdObject) throws IOException, GeneralSecurityException, JsonLDException {
        return this.sign(jsonLdObject, true, false);
    }

    public JsonLDObject deriveProof(JsonLDObject jsonLDObject, JsonLDObject frameJsonLDObject, boolean addToJsonLdObject, boolean defaultContexts) throws IOException, GeneralSecurityException, JsonLDException, JsonLdError {
        // check of signature suite supports proof derivation
        if(!(signatureSuite instanceof BbsBlsSignatureProof2020SignatureSuite)){
            throw new GeneralSecurityException("suite doesn't support derivation of proof: " + signatureSuite.getClass().getName());
        }

        // get input proof
        LdProof inputLdProof = LdProof.getFromJsonLDObject(jsonLDObject);
        // check if input proof is suitable for deriving proof
        if(!((BbsBlsSignatureProof2020SignatureSuite)signatureSuite).getSupportedJsonLDProofs().contains(inputLdProof.getType())){
            throw new GeneralSecurityException("derive proof not supported for proof type: " + inputLdProof.getType());
        }

        // remove ldProof from input document
        LdProof.removeFromJsonLdObject(jsonLDObject);

        // set nonce if not yet set
        if(nonce == null) nonce = Base64.getEncoder().encodeToString(RandomProvider.get().randomBytes(32));

        // extract signature from input proof and remove proof value
        byte[] signature = Base64.getDecoder().decode(inputLdProof.getProofValue());
        LdProof.removeLdProofValues(inputLdProof);

        // framing
        //get frame document
        JsonDocument frameDocument = JsonDocument.of(MediaType.JSON_LD, frameJsonLDObject.toJsonObject());

        //prepare input document
        // normalize
        String normalized = jsonLDObject.normalize(null);
        // transforms blank node id's to proper ones
        String transformedStatements = Arrays.stream(normalized.split("\n")).map(statement -> statement.replaceAll("_:c14n[0-9]*", "<urn:bnid:$0>")).collect(Collectors.joining("\n"));
        // convert back to jsonld
        JsonDocument expandedInputDocument = JsonDocument.of(JsonLd.fromRdf(RdfDocument.of(new ByteArrayInputStream(transformedStatements.getBytes()))).get());
        // frame input document and convert back to JsonLDObject
        JsonLDObject framedJsonLDObject = JsonLDObject.fromJson(JsonLd.frame(expandedInputDocument, frameDocument).get().toString());

        // canonicalize input jsonLdObject and framed input jsonLdObject
        List<String> canonicalDocument = this.getCanonicalizer().canonicalize(inputLdProof, jsonLDObject);
        List<String> canonicalFramedDocument = this.getCanonicalizer().canonicalize(inputLdProof, framedJsonLDObject);
        // transforms proper blank nodes back to simple id's in order to match format of input jsonLdObject
        canonicalFramedDocument = canonicalFramedDocument.stream().map(statement -> statement.replaceAll("<urn:bnid:(_:c14n[0-9]*)>", "$1")).collect(Collectors.toList());

        // calculate list of ProofMessages by comparing input and framed jsonLdObject line by line
        List<ProofMessage> messages = new ArrayList<>();
        int j = 0;
        for (String s : canonicalDocument) {
            int type;
            if (s.equals(canonicalFramedDocument.get(j))) {
                type = ProofMessage.PROOF_MESSAGE_TYPE_REVEALED;
                j++;
            } else {
                type = ProofMessage.PROOF_MESSAGE_TYPE_HIDDEN_PROOF_SPECIFIC_BLINDING;
            }
            messages.add(new ProofMessage(type, s.getBytes(), null));
        }

        // initialize the derived proof builder
        LdProof.Builder derivedProofBuilder = LdProof.builder()
                .defaultContexts(false)
                .defaultTypes(false)
                .created(inputLdProof.getCreated())
                .domain(inputLdProof.getDomain())
                .challenge(inputLdProof.getChallenge())
                .proofPurpose(inputLdProof.getProofPurpose())
                .verificationMethod(inputLdProof.getVerificationMethod())
                .type(this.getSignatureSuite().getTerm())
                .nonce(this.getNonce());

        // calculate proof value and add to derived proof
        ((BbsLdSigner<?>)this).deriveProof(derivedProofBuilder, signature, messages);

        // build derived proof
        JsonLDObject result = derivedProofBuilder.build();

        // add proof to framed document and reveal resulting document or return derived proof only
        if (addToJsonLdObject) {
            result.addToJsonLDObject(framedJsonLDObject);
            result = framedJsonLDObject;
        }

        return result;
    }

    public JsonLDObject deriveProof(JsonLDObject jsonLdObject, JsonLDObject frameJsonLdObject) throws IOException, GeneralSecurityException, JsonLDException, JsonLdError {
        return this.deriveProof(jsonLdObject, frameJsonLdObject, true, false);
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
