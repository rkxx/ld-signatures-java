package info.weboftrust.ldsignatures.canonicalizer;

import foundation.identity.jsonld.JsonLDException;
import foundation.identity.jsonld.JsonLDObject;
import info.weboftrust.ldsignatures.LdProof;
import org.bouncycastle.jcajce.provider.digest.Blake2b;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class URDNA2015BbsCanonicalizer extends Canonicalizer {

    public URDNA2015BbsCanonicalizer() {

        super(List.of("urdna2015"));
    }

    @Override
    public List<String> canonicalize(LdProof ldProof, JsonLDObject jsonLdObject) throws IOException, GeneralSecurityException, JsonLDException {

        // construct the LD proof without proof values

        LdProof ldProofWithoutProofValues = LdProof.builder()
                .base(ldProof)
                .defaultContexts(true)
                .build();
        LdProof.removeLdProofValues(ldProofWithoutProofValues);

        // construct the LD object without proof

        JsonLDObject jsonLdObjectWithoutProof = JsonLDObject.builder()
                .base(jsonLdObject)
                .build();
        jsonLdObjectWithoutProof.setDocumentLoader(jsonLdObject.getDocumentLoader());
        LdProof.removeFromJsonLdObject(jsonLdObjectWithoutProof);

        // canonicalize the LD proof and LD object

        String canonicalizedLdProofWithoutProofValues = ldProofWithoutProofValues.normalize("urdna2015");
        String canonicalizedJsonLdObjectWithoutProof = jsonLdObjectWithoutProof.normalize("urdna2015");

        // put all statements in one list and return

        List<String> statements = Arrays.stream(canonicalizedLdProofWithoutProofValues.split("\n")).collect(Collectors.toList());
        statements.addAll(Arrays.stream(canonicalizedJsonLdObjectWithoutProof.split("\n")).collect(Collectors.toList()));
        return statements;
    }
}
