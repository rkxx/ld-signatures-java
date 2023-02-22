package info.weboftrust.ldsignatures.canonicalizer;

import foundation.identity.jsonld.JsonLDException;
import foundation.identity.jsonld.JsonLDObject;
import info.weboftrust.ldsignatures.LdProof;
import org.bouncycastle.crypto.digests.Blake2bDigest;
import org.bouncycastle.jcajce.provider.digest.Blake2b;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class URDNA2015Canonicalizer extends Canonicalizer {

    public URDNA2015Canonicalizer() {

        super(List.of("urdna2015"));
    }

    @Override
    public List<byte[]> canonicalize(LdProof ldProof, JsonLDObject jsonLdObject) throws IOException, GeneralSecurityException, JsonLDException {

        // construct the LD object without proof

        JsonLDObject jsonLdObjectWithoutProof = JsonLDObject.builder()
                .base(jsonLdObject)
                .build();
        jsonLdObjectWithoutProof.setDocumentLoader(jsonLdObject.getDocumentLoader());
        LdProof.removeFromJsonLdObject(jsonLdObjectWithoutProof);

        // canonicalize the LD proof and LD object

        String canonicalizedJsonLdObjectWithoutProof = jsonLdObjectWithoutProof.normalize("urdna2015");

        // transform blank nodes id's to to proper ones and get bytes

        return Arrays.stream(canonicalizedJsonLdObjectWithoutProof.split("\n")).map(statement -> {
            byte[] bytes = statement.replaceAll("_:c14n[0-9]*", "<urn:bind:$0>").getBytes();
        // TODO: validate that statement digest algorithm requires Blake2b256, it just defines Blake2b without length
            Blake2b.Blake2b256 blake = new Blake2b.Blake2b256();
            return blake.digest(bytes);
        }).collect(Collectors.toList());
    }
}
