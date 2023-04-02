package info.weboftrust.ldsignatures.suites;

import com.danubetech.keyformats.jose.JWSAlgorithm;
import com.danubetech.keyformats.jose.KeyTypeName;
import info.weboftrust.ldsignatures.jsonld.LDSecurityContexts;

import java.net.URI;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public class BbsBlsSignatureProof2020SignatureSuite extends SignatureSuite {

    private List<String> supportedJsonLDProofs;

    BbsBlsSignatureProof2020SignatureSuite() {

        super(
                "BbsBlsSignatureProof2020",
                URI.create("https://w3id.org/security#BbsBlsSignatureProof2020"),
                URI.create("https://w3id.org/security#URDNA2015"),
                URI.create("https://www.blake2.net/"),
                URI.create("https://electriccoin.co/blog/new-snark-curve/"),
                List.of(KeyTypeName.Bls12381G1,
                        KeyTypeName.Bls12381G2),
                Map.of(KeyTypeName.Bls12381G1, List.of(JWSAlgorithm.BBSPlus),
                        KeyTypeName.Bls12381G2, List.of(JWSAlgorithm.BBSPlus)),
                Arrays.asList(LDSecurityContexts.JSONLD_CONTEXT_W3ID_SECURITY_BBS_V1, LDSecurityContexts.JSONLD_CONTEXT_W3ID_SECURITY_V3));
        supportedJsonLDProofs = List.of(
                "BbsBlsSignature2020",
                "sec:BbsBlsSignature2020",
                "https://w3id.org/security#BbsBlsSignature2020"
        );
    }

    public List<String> getSupportedJsonLDProofs() {
        return supportedJsonLDProofs;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        BbsBlsSignatureProof2020SignatureSuite that = (BbsBlsSignatureProof2020SignatureSuite) o;
        return Objects.equals(getTerm(), that.getTerm()) && Objects.equals(getId(), that.getId()) && Objects.equals(getType(), that.getType()) && Objects.equals(getCanonicalizationAlgorithm(), that.getCanonicalizationAlgorithm()) && Objects.equals(getDigestAlgorithm(), that.getDigestAlgorithm()) && Objects.equals(getProofAlgorithm(), that.getProofAlgorithm()) && Objects.equals(getKeyTypeNames(), that.getKeyTypeNames()) && Objects.equals(getJwsAlgorithmsForKeyTypeName(), that.getJwsAlgorithmsForKeyTypeName()) && Objects.equals(getSupportedJsonLDContexts(), that.getSupportedJsonLDContexts()) && Objects.equals(getSupportedJsonLDProofs(), that.getSupportedJsonLDProofs());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getTerm(), getId(), getType(), getCanonicalizationAlgorithm(), getDigestAlgorithm(), getProofAlgorithm(), getKeyTypeNames(), getJwsAlgorithmsForKeyTypeName(), getSupportedJsonLDContexts(), supportedJsonLDProofs);
    }

    @Override
    public String toString() {
        return "SignatureSuite{" +
                "term='" + getTerm() + '\'' +
                ", id=" + getId() +
                ", type=" + getType() +
                ", canonicalizationAlgorithm=" + getCanonicalizationAlgorithm() +
                ", digestAlgorithm=" + getDigestAlgorithm() +
                ", proofAlgorithm=" + getProofAlgorithm() +
                ", keyTypeNames=" + getKeyTypeNames() +
                ", jwsAlgorithmForKeyTypeName=" + getJwsAlgorithmsForKeyTypeName() +
                ", supportedJsonLDContexts=" + getSupportedJsonLDContexts() +
                ", supportedJsonLdTypes=" + supportedJsonLDProofs +
                '}';
    }
}
